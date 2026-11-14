#!/usr/bin/env python3
"""iamlint: offline linter for AWS IAM / S3 / KMS / SQS policy JSON documents.

Reads policy documents (files or stdin), reports over-broad or risky statements
and gives a concrete fix for each finding. It never contacts AWS and never
evaluates anything beyond the JSON it is given.

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage/input error.
"""
import argparse
import fnmatch
import json
import os
import re
import stat
import sys

__version__ = "1.0.0"

MAX_BYTES = 5 * 1024 * 1024
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAME = {v: k.upper() for k, v in SEV.items()}

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def clean(s, limit=160):
    s = _CTRL_RE.sub("?", str(s))
    return s if len(s) <= limit else s[:limit - 3] + "..."


# Single actions that can let a principal raise its own or another identity's privileges.
PRIVESC_SINGLE = {
    "iam:createpolicyversion": "can publish a new default version of a managed policy, rewriting what it allows",
    "iam:setdefaultpolicyversion": "can switch a managed policy to an older, more permissive version",
    "iam:attachuserpolicy": "can attach any managed policy (including admin) to a user",
    "iam:attachgrouppolicy": "can attach any managed policy (including admin) to a group",
    "iam:attachrolepolicy": "can attach any managed policy (including admin) to a role",
    "iam:putuserpolicy": "can write an inline policy on a user",
    "iam:putgrouppolicy": "can write an inline policy on a group",
    "iam:putrolepolicy": "can write an inline policy on a role",
    "iam:createaccesskey": "can mint credentials for other users",
    "iam:createloginprofile": "can set a console password for a user that has none",
    "iam:updateloginprofile": "can reset another user's console password",
    "iam:addusertogroup": "can add a user to a more privileged group",
    "iam:updateassumerolepolicy": "can change who may assume a role (its trust policy)",
    "sts:assumerole": "can assume any role whose trust policy allows this account",
}

# (required actions, description). PassRole-based combinations pivot through a service.
PRIVESC_COMBOS = [
    (["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
     "pass a privileged role to a new Lambda function and run code as that role"),
    (["iam:passrole", "lambda:updatefunctioncode"],
     "update the code of a Lambda function that runs with a privileged role"),
    (["iam:passrole", "ec2:runinstances"],
     "launch an instance whose instance profile carries a privileged role"),
    (["iam:passrole", "cloudformation:createstack"],
     "create a stack that provisions resources using a privileged role"),
    (["iam:passrole", "glue:createdevendpoint"],
     "start a Glue dev endpoint that runs as a privileged role"),
    (["iam:passrole", "ecs:runtask", "ecs:registertaskdefinition"],
     "register and run a container task under a privileged role"),
    (["iam:passrole", "sagemaker:createnotebookinstance"],
     "start a notebook that runs as a privileged role"),
    (["iam:passrole", "datapipeline:createpipeline", "datapipeline:putpipelinedefinition"],
     "define a pipeline that runs commands as a privileged role"),
]

# Actions that move data out or expose it to other accounts when granted on Resource "*".
EXFIL = {
    "s3:getobject": (2, "read any object in any bucket"),
    "s3:getobjectversion": (2, "read any object version in any bucket"),
    "secretsmanager:getsecretvalue": (3, "read every secret"),
    "ssm:getparameter": (2, "read every parameter, including SecureString after decrypt"),
    "ssm:getparameters": (2, "read every parameter"),
    "ssm:getparametersbypath": (2, "read whole parameter trees"),
    "kms:decrypt": (3, "decrypt data under every key"),
    "dynamodb:scan": (2, "dump whole tables"),
    "dynamodb:exporttabletopointintime": (3, "export whole tables to S3"),
    "rds:modifydbsnapshotattribute": (3, "share database snapshots with other accounts"),
    "ec2:modifysnapshotattribute": (3, "share disk snapshots with other accounts"),
    "ec2:modifyimageattribute": (3, "share machine images with other accounts"),
    "s3:putbucketpolicy": (3, "rewrite any bucket policy, e.g. to make it public"),
    "s3:putbucketacl": (3, "change any bucket ACL"),
    "s3:putobjectacl": (2, "change object ACLs"),
    "sqs:receivemessage": (2, "drain any queue"),
}

STRONG_COND_KEYS = {
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid", "aws:principalaccount",
    "aws:principalarn", "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:userid",
    "aws:resourceorgid", "aws:sourceorgid", "aws:principalorgpaths", "aws:sourceorgpaths",
    "sts:externalid", "aws:resourceaccount", "aws:principalservicename", "aws:federatedprovider",
    "cognito-identity.amazonaws.com:aud", "token.actions.githubusercontent.com:sub",
}


class Finding(object):
    def __init__(self, rule, severity, source, where, message, fix):
        self.rule = rule
        self.severity = severity
        self.source = clean(source)
        self.where = clean(where)
        self.message = clean(message, 400)
        self.fix = clean(fix, 400)

    def as_dict(self):
        return {"rule": self.rule, "severity": SEV_NAME[self.severity], "file": self.source,
                "statement": self.where, "message": self.message, "fix": self.fix}


class InputError(Exception):
    pass


# --------------------------------------------------------------- loading

def read_file(path, stdin=None):
    if path == "-":
        stream = stdin if stdin is not None else sys.stdin.buffer
        data = stream.read(MAX_BYTES + 1)
    else:
        try:
            st = os.stat(path)
        except OSError as e:
            raise InputError("cannot read: %s" % (e.strerror or e))
        if not stat.S_ISREG(st.st_mode):
            raise InputError("not a regular file")
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise InputError("cannot read: %s" % (e.strerror or e))
    if len(data) > MAX_BYTES:
        raise InputError("larger than %d MiB, refusing" % (MAX_BYTES // 1024 // 1024))
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputError("not valid UTF-8 text")


def find_document(obj, depth=0):
    """Locate the policy document in a bare policy or a CLI/API wrapper object."""
    if isinstance(obj, str) and depth < 4:
        try:
            return find_document(json.loads(obj), depth + 1)
        except (ValueError, RecursionError):
            return None
    if not isinstance(obj, dict) or depth > 4:
        return None
    if "Statement" in obj:
        return obj
    for key in ("PolicyDocument", "AssumeRolePolicyDocument", "Document", "PolicyVersion", "Policy",
                "Attributes", "KeyPolicy", "Role", "Policies"):
        if key in obj:
            found = find_document(obj[key], depth + 1)
            if found is not None:
                return found
    return None


def parse_document(text):
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        raise InputError("not valid JSON")
    doc = find_document(obj)
    if doc is None:
        raise InputError("no policy document found (no \"Statement\" key)")
    return doc


# --------------------------------------------------------------- helpers

def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def strs(v):
    return [x for x in as_list(v) if isinstance(x, str)]


def action_grants(patterns, target):
    """Does any pattern grant `target`? Bare '*' and 'service:*' are handled by their own rules."""
    t = target.lower()
    for p in patterns:
        pl = p.lower()
        if pl == "*" or pl.endswith(":*"):
            continue
        if fnmatch.fnmatchcase(t, pl):
            return True
    return False


def resource_broad(stmt):
    """'*' exactly (or NotResource) => 2; any other wildcard => 1; else 0."""
    if "NotResource" in stmt:
        return 2
    res = strs(stmt.get("Resource"))
    if "*" in res:
        return 2
    if any("*" in r for r in res):
        return 1
    return 0


def cond_keys(cond):
    """Return (set of lowercase keys, set of weak keys whose values are match-everything)."""
    keys, weak = set(), set()
    if not isinstance(cond, dict):
        return keys, weak
    for op, body in cond.items():
        if not isinstance(body, dict):
            continue
        for k, v in body.items():
            if not isinstance(k, str):
                continue
            kl = k.lower()
            keys.add(kl)
            vals = [str(x) for x in as_list(v)]
            if any(x.strip() in ("*", "0.0.0.0/0", "::/0", "arn:aws:*:*:*:*") for x in vals):
                weak.add(kl)
    return keys, weak


def principals(stmt):
    """Flatten Principal into a list of (kind, value)."""
    p = stmt.get("Principal")
    out = []
    if isinstance(p, str):
        out.append(("AWS", p))
    elif isinstance(p, dict):
        for kind, v in p.items():
            for x in strs(v):
                out.append((kind, x))
    return out


def is_trust(stmt):
    acts = [a.lower() for a in strs(stmt.get("Action"))]
    return any(a in ("sts:assumerole", "sts:assumerolewithsaml", "sts:assumerolewithwebidentity",
                     "sts:assumerole*", "sts:*", "sts:tagsession", "sts:setsourceidentity") or
               fnmatch.fnmatchcase("sts:assumerole", a) and a != "*" for a in acts)


# --------------------------------------------------------------- linting

def lint_document(doc, source="<stdin>"):
    findings = []

    def add(rule, sev, where, msg, fix):
        findings.append(Finding(rule, sev, source, where, msg, fix))

    version = doc.get("Version")
    if version is None:
        add("IAM-VERSION", 1, "document", "no Version element; the default is the old 2008-10-17 language",
            'Add "Version": "2012-10-17" at the top of the policy')
    elif version == "2008-10-17":
        add("IAM-VERSION", 2, "document",
            "Version 2008-10-17 is the old policy language: policy variables such as ${aws:username} are not substituted",
            'Change to "Version": "2012-10-17" and re-test the policy')
    elif version != "2012-10-17":
        add("IAM-VERSION", 1, "document", "unrecognised Version %s" % clean(version, 40),
            'Use "Version": "2012-10-17", the only current policy language version')

    raw = doc.get("Statement")
    stmts = as_list(raw)
    if not stmts:
        add("IAM-MALFORMED", 2, "document", "policy has no statements", "Add at least one Statement")
    sids = {}
    allow_stmts = []  # (where, stmt)
    for i, st in enumerate(stmts):
        if not isinstance(st, dict):
            add("IAM-MALFORMED", 2, "#%d" % (i + 1), "statement is not a JSON object",
                "Rewrite the statement as an object with Effect, Action and Resource")
            continue
        sid = st.get("Sid")
        where = ("%s (#%d)" % (clean(sid, 60), i + 1)) if isinstance(sid, str) and sid else "#%d" % (i + 1)
        if isinstance(sid, str) and sid:
            sids.setdefault(sid, []).append(where)
        effect = st.get("Effect")
        if effect not in ("Allow", "Deny"):
            add("IAM-MALFORMED", 2, where, "Effect must be \"Allow\" or \"Deny\"",
                'Set "Effect": "Allow" or "Deny"')
            continue
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in st and not all(isinstance(x, str) for x in as_list(st[key])):
                add("IAM-MALFORMED", 2, where, "%s contains a non-string value" % key,
                    "Use only strings in %s" % key)
        if effect != "Allow":
            continue
        allow_stmts.append((where, st))
        lint_allow(st, where, add)

    for sid, wheres in sids.items():
        if len(wheres) > 1:
            add("IAM-DUP-SID", 2, ", ".join(wheres[:4]),
                "Sid %s is used by %d statements; Sids must be unique within a policy" % (clean(sid, 40), len(wheres)),
                "Give each statement a distinct Sid (or remove them)")

    lint_combos(allow_stmts, add)
    findings.sort(key=lambda f: (-f.severity, f.where, f.rule))
    return findings


def lint_allow(st, where, add):
    actions = strs(st.get("Action"))
    low = [a.lower() for a in actions]
    res = strs(st.get("Resource"))
    cond = st.get("Condition")
    has_cond = bool(cond)
    broad = resource_broad(st)
    trust = is_trust(st)
    star_res = broad == 2

    if "*" in actions:
        add("IAM-ACTION-STAR", 4 if star_res and not has_cond else 3, where,
            'Allow with Action "*"%s' % (' on Resource "*": full administrator access' if star_res else ""),
            "List only the actions this principal needs; start from IAM Access Analyzer generated policies "
            "or the service's access-level docs")
    else:
        for a in actions:
            if a.endswith(":*") and not (a.lower() == "s3:*"):
                add("IAM-SERVICE-WILDCARD", 3 if star_res else 2, where,
                    "Allow with %s (every action in the service)%s" % (clean(a, 60), ' on Resource "*"' if star_res else ""),
                    "Replace %s with the specific actions needed, or a narrower prefix such as %s" %
                    (clean(a, 60), clean(a.split(":")[0], 30) + ":Get*"))
    if any(a.lower() == "s3:*" for a in actions):
        add("IAM-S3-STAR", 3, where,
            's3:* allows deleting buckets, changing bucket policies and reading all objects%s' %
            (' on Resource "*" (every bucket)' if star_res else ""),
            "Grant s3:GetObject/s3:PutObject on arn:aws:s3:::BUCKET/PREFIX/* and s3:ListBucket on the bucket only")

    if "NotAction" in st:
        add("IAM-NOTACTION-ALLOW", 3, where,
            "Allow with NotAction grants every action except the listed ones, including future ones",
            "Replace NotAction with an explicit Action list, or pair a broad Allow with an explicit Deny")
    if "NotResource" in st:
        add("IAM-NOTRESOURCE-ALLOW", 3, where,
            "Allow with NotResource applies to every resource except the listed ones",
            "List the intended resources in Resource instead")
    if "NotPrincipal" in st:
        add("IAM-NOTPRINCIPAL-ALLOW", 3, where,
            "Allow with NotPrincipal grants access to everyone except the listed principals",
            "Name the intended principals in Principal; use NotPrincipal only with Deny")

    # Resource "*" on its own (not already reported through a star action)
    if star_res and "*" not in actions and "NotResource" not in st and actions:
        harmless = all(re.match(r"^[a-z0-9-]+:(describe|list)", a.lower()) for a in actions)
        add("IAM-RESOURCE-STAR", 1 if harmless else 2, where,
            'Allow on Resource "*" applies to every resource in the account%s' %
            (" (read-only listing, low risk)" if harmless else ""),
            "Scope Resource to specific ARNs, or add a Condition (aws:ResourceTag, aws:RequestedRegion) to limit it")

    # iam:PassRole on *
    if action_grants(actions, "iam:PassRole") or "iam:passrole" in low:
        if star_res and not any(k == "iam:passedtoservice" for k in cond_keys(cond)[0]):
            add("IAM-PASSROLE-STAR", 3, where,
                'iam:PassRole on Resource "*" lets the principal hand any role in the account to a service it can start',
                "Limit Resource to the exact role ARNs and add Condition StringEquals iam:PassedToService")

    # privilege escalation singles (explicit actions only; star actions have their own rules)
    if broad and "NotAction" not in st:
        for act, why in sorted(PRIVESC_SINGLE.items()):
            if action_grants(actions, act):
                sev = 3 if broad == 2 else 2
                if act == "sts:assumerole" and broad != 2:
                    continue
                add("IAM-PRIVESC", sev, where,
                    "%s on %s: %s" % (act, 'Resource "*"' if broad == 2 else "a wildcard resource", why),
                    "Restrict Resource to specific ARNs, add a permissions boundary or Condition, "
                    "and keep this action to a small administrator role")

    # exfil-prone on *
    if star_res and "NotAction" not in st:
        seen_desc = set()
        for act, (sev, why) in sorted(EXFIL.items()):
            if action_grants(actions, act) and why not in seen_desc:
                seen_desc.add(why)
                add("IAM-EXFIL-STAR", sev, where,
                    '%s on Resource "*" can %s' % (act, why),
                    "Scope Resource to the specific buckets/secrets/keys/tables the workload uses")

    # principals
    plist = principals(st)
    if plist:
        wild = [(k, v) for k, v in plist if "*" in v]
        keys, weak = cond_keys(cond)
        strong = (keys - weak) & STRONG_COND_KEYS
        if trust:
            for k, v in wild:
                full = v == "*"
                add("IAM-TRUST-WILDCARD", 4 if full and not has_cond else 3, where,
                    "trust policy principal %s%s allows %s to assume this role" %
                    (clean(v, 80), "" if not has_cond else " (with a Condition)",
                     "anyone on the internet with AWS credentials" if full else "a pattern-matched set of identities"),
                    "Name the exact role/account ARNs in Principal; for cross-account add sts:ExternalId or aws:PrincipalOrgID")
        else:
            for k, v in wild:
                if v != "*":
                    continue
                if not has_cond:
                    add("IAM-PRINCIPAL-STAR", 3, where,
                        'Principal "*" with no Condition makes this statement public to everyone',
                        "Name the intended principals, or add a Condition such as aws:PrincipalOrgID, "
                        "aws:SourceVpce, aws:SourceArn/aws:SourceAccount (for AWS services)")
                elif not strong:
                    add("IAM-PRINCIPAL-STAR-WEAKCOND", 2, where,
                        'Principal "*" has a Condition, but none that restricts who the caller is',
                        "Add aws:PrincipalOrgID, aws:PrincipalAccount, aws:SourceVpce, aws:SourceIp or aws:SourceArn")
                break
            # AWS service principals without SourceArn/SourceAccount: confused deputy (only for resource policies)
            for k, v in plist:
                if k == "Service" and not (keys & {"aws:sourcearn", "aws:sourceaccount", "aws:sourceowner"}):
                    if v.endswith(("sns.amazonaws.com", "s3.amazonaws.com", "events.amazonaws.com")):
                        add("IAM-SERVICE-NO-SOURCE", 1, where,
                            "service principal %s without aws:SourceArn/aws:SourceAccount (confused deputy risk)" % clean(v, 60),
                            "Add Condition ArnLike aws:SourceArn and StringEquals aws:SourceAccount")
                        break


def lint_combos(allow_stmts, add):
    if not allow_stmts:
        return
    per_action = {}
    for where, st in allow_stmts:
        if "NotAction" in st:
            continue
        actions = strs(st.get("Action"))
        broad = resource_broad(st)
        per_action.setdefault("_", []).append((where, actions, broad))
    entries = per_action.get("_", [])

    def grant(target):
        best = 0
        where = None
        for w, acts, broad in entries:
            if action_grants(acts, target):
                if broad + 1 > best:
                    best, where = broad + 1, w
        return best, where

    passrole, pr_where = grant("iam:PassRole")
    if passrole < 3:  # only PassRole on "*" is dangerous enough to combine
        return
    for needs, desc in PRIVESC_COMBOS:
        ok = True
        for act in needs[1:]:
            lvl, _ = grant(act)
            if lvl == 0:
                ok = False
                break
        if ok:
            add("IAM-PRIVESC-COMBO", 3, pr_where,
                "%s together with %s can be used to %s" % ("iam:PassRole", ", ".join(needs[1:]), desc),
                "Remove one of the actions, restrict iam:PassRole to exact role ARNs with iam:PassedToService, "
                "and apply a permissions boundary")


# --------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="iamlint",
        description="Offline linter for AWS IAM/S3/KMS/SQS policy JSON. Never contacts AWS.",
        epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage or input error.")
    p.add_argument("files", nargs="*", help="policy JSON files; - or none reads stdin")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="low",
                   help="lowest severity that makes the exit code 1 (default: low = any finding)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="skip a rule id such as IAM-RESOURCE-STAR (repeatable)")
    p.add_argument("--version", action="version", version="iamlint " + __version__)
    return p


def main(argv=None, stdin=None, stdout=None):
    out = stdout if stdout is not None else sys.stdout
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    files = args.files or ["-"]
    ignore = set(r.upper() for r in args.ignore)
    all_findings, errors = [], []
    for path in files:
        name = "<stdin>" if path == "-" else path
        try:
            doc = parse_document(read_file(path, stdin))
            all_findings.extend(f for f in lint_document(doc, name) if f.rule not in ignore)
        except InputError as e:
            errors.append({"file": clean(name), "error": str(e)})
        except RecursionError:
            errors.append({"file": clean(name), "error": "nested too deeply"})
    threshold = None if args.fail_on == "never" else SEV[args.fail_on]
    failing = [f for f in all_findings if threshold is not None and f.severity >= threshold]
    code = 2 if errors else (1 if failing else 0)
    if args.json:
        out.write(json.dumps({"tool": "iamlint", "version": __version__,
                              "findings": [f.as_dict() for f in all_findings],
                              "errors": errors, "exit": code}, indent=2) + "\n")
    else:
        for f in all_findings:
            out.write("%-8s %-26s %s: %s\n" % (SEV_NAME[f.severity], f.rule, f.source, f.where))
            out.write("         %s\n         fix: %s\n" % (f.message, f.fix))
        for e in errors:
            out.write("error: %s: %s\n" % (e["file"], e["error"]))
        if not all_findings and not errors:
            out.write("iamlint: no findings in %d document(s)\n" % len(files))
        elif all_findings:
            out.write("iamlint: %d finding(s)\n" % len(all_findings))
    for e in errors:
        sys.stderr.write("iamlint: error: %s: %s\n" % (e["file"], e["error"]))
    return code


if __name__ == "__main__":
    sys.exit(main())
