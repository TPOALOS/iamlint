import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

import iamlint as il

HERE = os.path.dirname(os.path.abspath(__file__))


def pol(*stmts, **kw):
    d = {"Version": "2012-10-17", "Statement": list(stmts)}
    d.update(kw)
    return d


def allow(action, resource="*", **kw):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    s.update(kw)
    return s


def lint(doc):
    return il.lint_document(doc, "t.json")


def ids(f):
    return [x.rule for x in f]


def cli(argv, stdin_text=None):
    out = io.StringIO()
    stdin = io.BytesIO(stdin_text.encode() if isinstance(stdin_text, str) else (stdin_text or b""))
    return il.main(argv, stdin=stdin, stdout=out), out.getvalue()


class TestWildcards(unittest.TestCase):
    def test_admin_star_critical(self):
        f = lint(pol(allow("*")))
        self.assertIn("IAM-ACTION-STAR", ids(f))
        self.assertEqual(f[0].severity, 4)

    def test_star_action_specific_resource_high(self):
        f = lint(pol(allow("*", "arn:aws:s3:::b")))
        self.assertEqual([x for x in f if x.rule == "IAM-ACTION-STAR"][0].severity, 3)

    def test_service_wildcard(self):
        f = lint(pol(allow("ec2:*", "arn:aws:ec2:us-east-1:111122223333:instance/*")))
        self.assertEqual(ids(f), ["IAM-SERVICE-WILDCARD"])

    def test_service_wildcard_star_resource_high(self):
        f = lint(pol(allow("kms:*")))
        self.assertEqual([x for x in f if x.rule == "IAM-SERVICE-WILDCARD"][0].severity, 3)

    def test_resource_star_medium(self):
        f = lint(pol(allow("ec2:StartInstances")))
        r = [x for x in f if x.rule == "IAM-RESOURCE-STAR"][0]
        self.assertEqual(r.severity, 2)

    def test_resource_star_describe_low(self):
        f = lint(pol(allow(["ec2:DescribeInstances", "ec2:DescribeVolumes"])))
        self.assertEqual(f[0].severity, 1)

    def test_clean_policy(self):
        f = lint(pol(allow("s3:GetObject", "arn:aws:s3:::bucket/prefix/*", Sid="Read")))
        self.assertEqual(f, [])

    def test_s3_star(self):
        f = lint(pol(allow("s3:*", "arn:aws:s3:::bucket")))
        self.assertEqual(ids(f), ["IAM-S3-STAR"])

    def test_s3_star_all_buckets(self):
        f = lint(pol(allow("s3:*")))
        self.assertIn("IAM-S3-STAR", ids(f))

    def test_deny_star_not_flagged(self):
        f = lint(pol({"Effect": "Deny", "Action": "*", "Resource": "*"}))
        self.assertEqual(f, [])


class TestNotElements(unittest.TestCase):
    def test_notaction_allow(self):
        f = lint(pol({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
        self.assertIn("IAM-NOTACTION-ALLOW", ids(f))

    def test_notaction_deny_ok(self):
        f = lint(pol({"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"}))
        self.assertEqual(f, [])

    def test_notresource_allow(self):
        f = lint(pol({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"}))
        self.assertIn("IAM-NOTRESOURCE-ALLOW", ids(f))

    def test_notprincipal_allow(self):
        f = lint(pol({"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"},
                      "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}))
        self.assertIn("IAM-NOTPRINCIPAL-ALLOW", ids(f))


class TestPrincipals(unittest.TestCase):
    def test_principal_star_no_condition(self):
        f = lint(pol({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}))
        self.assertEqual(ids(f), ["IAM-PRINCIPAL-STAR"])

    def test_principal_aws_star_dict(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sqs:SendMessage",
                      "Resource": "arn:aws:sqs:us-east-1:111122223333:q"}))
        self.assertEqual(ids(f), ["IAM-PRINCIPAL-STAR"])

    def test_principal_star_strong_condition_ok(self):
        f = lint(pol({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                      "Resource": "arn:aws:s3:::b/*",
                      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example1234"}}}))
        self.assertEqual(f, [])

    def test_principal_star_weak_condition(self):
        f = lint(pol({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                      "Resource": "arn:aws:s3:::b/*",
                      "Condition": {"Bool": {"aws:SecureTransport": "true"}}}))
        self.assertEqual(ids(f), ["IAM-PRINCIPAL-STAR-WEAKCOND"])

    def test_condition_matching_everything_is_weak(self):
        f = lint(pol({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                      "Resource": "arn:aws:s3:::b/*",
                      "Condition": {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}}))
        self.assertEqual(ids(f), ["IAM-PRINCIPAL-STAR-WEAKCOND"])

    def test_specific_principal_ok(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/r"},
                      "Action": "sqs:SendMessage", "Resource": "arn:aws:sqs:us-east-1:111122223333:q"}))
        self.assertEqual(f, [])

    def test_kms_key_policy_wrapper(self):
        f = il.lint_document(il.find_document({"KeyPolicy": json.dumps(pol(
            {"Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"}))}), "k")
        self.assertIn("IAM-PRINCIPAL-STAR", ids(f))

    def test_trust_wildcard_full(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}))
        self.assertEqual(ids(f), ["IAM-TRUST-WILDCARD"])
        self.assertEqual(f[0].severity, 4)

    def test_trust_wildcard_partial(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::*:root"}, "Action": "sts:AssumeRole"}))
        self.assertEqual(f[0].rule, "IAM-TRUST-WILDCARD")
        self.assertEqual(f[0].severity, 3)

    def test_trust_specific_ok(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}))
        self.assertEqual(f, [])

    def test_confused_deputy_low(self):
        f = lint(pol({"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
                      "Resource": "arn:aws:sqs:us-east-1:111122223333:q"}))
        self.assertEqual(ids(f), ["IAM-SERVICE-NO-SOURCE"])


class TestPrivesc(unittest.TestCase):
    def test_passrole_star(self):
        f = lint(pol(allow("iam:PassRole")))
        self.assertIn("IAM-PASSROLE-STAR", ids(f))

    def test_passrole_scoped_ok(self):
        f = lint(pol(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app")))
        self.assertEqual(f, [])

    def test_passrole_with_passedtoservice_not_flagged_star(self):
        f = lint(pol(allow("iam:PassRole", "*", Condition={"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})))
        self.assertNotIn("IAM-PASSROLE-STAR", ids(f))

    def test_create_policy_version(self):
        f = lint(pol(allow("iam:CreatePolicyVersion")))
        self.assertIn("IAM-PRIVESC", ids(f))

    def test_attach_user_policy(self):
        f = lint(pol(allow(["iam:AttachUserPolicy", "iam:PutRolePolicy"])))
        self.assertEqual(ids(f).count("IAM-PRIVESC"), 2)

    def test_assume_role_star(self):
        f = lint(pol(allow("sts:AssumeRole")))
        self.assertIn("IAM-PRIVESC", ids(f))

    def test_assume_role_scoped_ok(self):
        f = lint(pol(allow("sts:AssumeRole", "arn:aws:iam::111122223333:role/x")))
        self.assertEqual(f, [])

    def test_privesc_specific_resource_not_flagged(self):
        f = lint(pol(allow("iam:AttachUserPolicy", "arn:aws:iam::111122223333:user/bob")))
        self.assertEqual(f, [])

    def test_combo_lambda(self):
        f = lint(pol(allow(["iam:PassRole", "lambda:UpdateFunctionCode"])))
        self.assertIn("IAM-PRIVESC-COMBO", ids(f))

    def test_combo_across_statements(self):
        f = lint(pol(allow("iam:PassRole", Sid="A"), allow("ec2:RunInstances", Sid="B")))
        self.assertIn("IAM-PRIVESC-COMBO", ids(f))

    def test_combo_needs_all_actions(self):
        f = lint(pol(allow(["iam:PassRole", "lambda:CreateFunction"])))
        self.assertNotIn("IAM-PRIVESC-COMBO", ids(f))

    def test_combo_not_when_passrole_scoped(self):
        f = lint(pol(allow("iam:PassRole", "arn:aws:iam::111122223333:role/a", Sid="A"),
                     allow("ec2:RunInstances", Sid="B")))
        self.assertNotIn("IAM-PRIVESC-COMBO", ids(f))

    def test_combo_wildcard_actions_dont_double_report(self):
        f = lint(pol(allow("*")))
        self.assertNotIn("IAM-PRIVESC", ids(f))

    def test_privesc_message_defensive(self):
        f = lint(pol(allow("iam:CreateAccessKey")))
        text = " ".join(x.message + x.fix for x in f).lower()
        self.assertNotIn("exploit", text)
        self.assertIn("restrict", text)


class TestExfil(unittest.TestCase):
    def test_secrets_star(self):
        f = lint(pol(allow("secretsmanager:GetSecretValue")))
        self.assertIn("IAM-EXFIL-STAR", ids(f))

    def test_kms_decrypt_star(self):
        f = lint(pol(allow("kms:Decrypt")))
        self.assertTrue(any(x.rule == "IAM-EXFIL-STAR" and x.severity == 3 for x in f))

    def test_wildcard_actions_match(self):
        f = lint(pol(allow("ssm:GetParam*")))
        self.assertIn("IAM-EXFIL-STAR", ids(f))

    def test_snapshot_sharing(self):
        f = lint(pol(allow("ec2:ModifySnapshotAttribute")))
        self.assertTrue(any(x.rule == "IAM-EXFIL-STAR" and x.severity == 3 for x in f))

    def test_exfil_scoped_ok(self):
        f = lint(pol(allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-*")))
        self.assertEqual(f, [])


class TestStructure(unittest.TestCase):
    def test_statement_as_dict(self):
        f = il.lint_document({"Version": "2012-10-17", "Statement": allow("*")}, "t")
        self.assertIn("IAM-ACTION-STAR", ids(f))

    def test_action_string_and_resource_list(self):
        f = lint(pol(allow("s3:GetObject", ["arn:aws:s3:::a/*", "*"])))
        self.assertIn("IAM-RESOURCE-STAR", ids(f))

    def test_old_version(self):
        f = il.lint_document({"Version": "2008-10-17", "Statement": [allow("s3:GetObject", "arn:aws:s3:::b/*")]}, "t")
        self.assertEqual(ids(f), ["IAM-VERSION"])
        self.assertEqual(f[0].severity, 2)

    def test_missing_version(self):
        f = il.lint_document({"Statement": [allow("s3:GetObject", "arn:aws:s3:::b/*")]}, "t")
        self.assertEqual(ids(f), ["IAM-VERSION"])

    def test_duplicate_sids(self):
        f = lint(pol(allow("s3:GetObject", "arn:aws:s3:::b/*", Sid="Same"),
                     allow("s3:PutObject", "arn:aws:s3:::b/*", Sid="Same")))
        self.assertEqual(ids(f), ["IAM-DUP-SID"])

    def test_unique_sids_ok(self):
        f = lint(pol(allow("s3:GetObject", "arn:aws:s3:::b/*", Sid="A"),
                     allow("s3:PutObject", "arn:aws:s3:::b/*", Sid="B")))
        self.assertEqual(f, [])

    def test_every_finding_has_fix(self):
        f = lint(pol(allow("*"), {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
                     allow(["iam:PassRole", "iam:CreatePolicyVersion", "kms:Decrypt"])))
        self.assertTrue(f and all(x.fix for x in f))

    def test_non_object_statement(self):
        f = lint(pol("oops", 5))
        self.assertEqual(ids(f), ["IAM-MALFORMED", "IAM-MALFORMED"])

    def test_bad_effect(self):
        f = lint(pol({"Effect": "Maybe", "Action": "*", "Resource": "*"}))
        self.assertEqual(ids(f), ["IAM-MALFORMED"])

    def test_non_string_action_no_crash(self):
        f = lint(pol({"Effect": "Allow", "Action": [1, None, {"a": 1}, "s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}))
        self.assertIn("IAM-MALFORMED", ids(f))

    def test_empty_statement_list(self):
        self.assertEqual(ids(lint(pol())), ["IAM-MALFORMED"])

    def test_cli_wrapper_policy_document(self):
        doc = il.parse_document(json.dumps({"Role": {"AssumeRolePolicyDocument": pol(
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})}}))
        self.assertIn("Statement", doc)

    def test_sqs_attributes_string_policy(self):
        doc = il.parse_document(json.dumps({"Attributes": {"Policy": json.dumps(pol(allow("sqs:*")))}}))
        self.assertIn("Statement", doc)

    def test_control_chars_in_sid_sanitised(self):
        f = lint(pol(allow("*", Sid="evil\x1b[31m\nINJECT‮")))
        code, out = cli([], json.dumps(pol(allow("*", Sid="evil\x1b[31m\nINJECT‮"))))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertEqual([l for l in out.splitlines() if l.startswith("INJECT")], [])
        self.assertTrue(f)


class TestHostileInput(unittest.TestCase):
    def test_not_json(self):
        self.assertEqual(cli([], "nope")[0], 2)

    def test_binary(self):
        self.assertEqual(cli([], b"\xff\xfe\x00garbage")[0], 2)

    def test_no_statement(self):
        self.assertEqual(cli([], '{"Version": "2012-10-17"}')[0], 2)

    def test_json_list_top_level(self):
        self.assertEqual(cli([], "[1,2,3]")[0], 2)

    def test_deep_nesting(self):
        self.assertEqual(cli([], "[" * 100000 + "]" * 100000)[0], 2)

    def test_deeply_nested_string_wrappers(self):
        s = json.dumps(pol(allow("*")))
        for _ in range(10):
            s = json.dumps({"Policy": s})
        self.assertEqual(cli([], s)[0], 2)

    def test_huge_file_refused(self):
        old = il.MAX_BYTES
        il.MAX_BYTES = 20
        try:
            code, _ = cli([], json.dumps(pol(allow("*"))))
        finally:
            il.MAX_BYTES = old
        self.assertEqual(code, 2)

    def test_missing_file(self):
        self.assertEqual(cli(["/nonexistent/p.json"])[0], 2)

    def test_directory(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cli([d])[0], 2)

    def test_fifo(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f")
            os.mkfifo(p)
            self.assertEqual(cli([p])[0], 2)

    def test_symlink_ok_and_dangling(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "p.json")
            with open(real, "w") as fh:
                json.dump(pol(allow("s3:GetObject", "arn:aws:s3:::b/*")), fh)
            link = os.path.join(d, "l.json")
            os.symlink(real, link)
            self.assertEqual(cli([link])[0], 0)
            dang = os.path.join(d, "d.json")
            os.symlink(os.path.join(d, "none"), dang)
            self.assertEqual(cli([dang])[0], 2)

    def test_filename_with_control_chars(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a\x1b[2Jb.json")
            with open(p, "w") as fh:
                json.dump(pol(allow("*")), fh)
            code, out = cli([p])
            self.assertEqual(code, 1)
            self.assertNotIn("\x1b", out)

    def test_never_executes_content(self):
        with open(os.path.join(HERE, "iamlint.py")) as fh:
            src = fh.read()
        for bad in ("subprocess", "os.system", "eval(", "exec(", "socket", "urllib"):
            self.assertNotIn(bad, src)


class TestCli(unittest.TestCase):
    def test_exit_0(self):
        code, out = cli([], json.dumps(pol(allow("s3:GetObject", "arn:aws:s3:::b/*"))))
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_exit_1(self):
        self.assertEqual(cli([], json.dumps(pol(allow("*"))))[0], 1)

    def test_fail_on_high(self):
        p = json.dumps(pol(allow(["ec2:DescribeInstances"])))
        self.assertEqual(cli(["--fail-on", "high"], p)[0], 0)
        self.assertEqual(cli([], p)[0], 1)

    def test_fail_on_never(self):
        self.assertEqual(cli(["--fail-on", "never"], json.dumps(pol(allow("*"))))[0], 0)

    def test_ignore_rule(self):
        p = json.dumps(pol(allow("ec2:StartInstances")))
        self.assertEqual(cli(["--ignore", "iam-resource-star"], p)[0], 0)

    def test_json_output(self):
        code, out = cli(["--json"], json.dumps(pol(allow("*"))))
        d = json.loads(out)
        self.assertEqual(d["tool"], "iamlint")
        self.assertEqual(d["exit"], 1)
        self.assertTrue(d["findings"][0]["fix"])

    def test_multiple_files_one_bad_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "g.json")
            with open(good, "w") as fh:
                json.dump(pol(allow("*")), fh)
            code, out = cli([good, os.path.join(d, "missing.json")])
            self.assertEqual(code, 2)
            self.assertIn("IAM-ACTION-STAR", out)

    def test_bad_flag(self):
        self.assertEqual(cli(["--bogus"])[0], 2)

    def test_subprocess_stdin(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "iamlint.py"), "--json", "-"],
                           input=json.dumps(pol(allow("*"))).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["findings"][0]["file"], "<stdin>")


if __name__ == "__main__":
    unittest.main()
