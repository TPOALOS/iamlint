# iamlint

**Find the over-broad IAM policy before it becomes an incident.** `Action: "*"`, `Resource: "*"`, a bucket policy with `Principal: "*"`,
a role anyone can assume, `iam:PassRole` on everything: these pass `aws iam create-policy` fine and stay in the account for years. iamlint reads
policy JSON (IAM identity policies, trust policies, S3 bucket policies, KMS key policies, SQS queue policies) from files or stdin, reports
what is risky and gives a concrete fix for each finding. Fully offline: it never calls AWS and only parses the JSON.

```
$ iamlint admin.json queue.json trust.json
CRITICAL IAM-ACTION-STAR            admin.json: All (#1)
         Allow with Action "*" on Resource "*": full administrator access
         fix: List only the actions this principal needs; start from IAM Access Analyzer generated policies or the service's access-level docs
HIGH     IAM-EXFIL-STAR             admin.json: All (#2)
         secretsmanager:getsecretvalue on Resource "*" can read every secret
         fix: Scope Resource to the specific buckets/secrets/keys/tables the workload uses
HIGH     IAM-PASSROLE-STAR          admin.json: All (#2)
         iam:PassRole on Resource "*" lets the principal hand any role in the account to a service it can start
         fix: Limit Resource to the exact role ARNs and add Condition StringEquals iam:PassedToService
HIGH     IAM-PRIVESC-COMBO          admin.json: All (#2)
         iam:PassRole together with lambda:updatefunctioncode can be used to update the code of a Lambda function that runs with a privileged role
         fix: Remove one of the actions, restrict iam:PassRole to exact role ARNs with iam:PassedToService, and apply a permissions boundary
MEDIUM   IAM-DUP-SID                admin.json: All (#1), All (#2)
         Sid All is used by 2 statements; Sids must be unique within a policy
         fix: Give each statement a distinct Sid (or remove them)
MEDIUM   IAM-RESOURCE-STAR          admin.json: All (#2)
         Allow on Resource "*" applies to every resource in the account
         fix: Scope Resource to specific ARNs, or add a Condition (aws:ResourceTag, aws:RequestedRegion) to limit it
MEDIUM   IAM-VERSION                admin.json: document
         Version 2008-10-17 is the old policy language: policy variables such as ${aws:username} are not substituted
         fix: Change to "Version": "2012-10-17" and re-test the policy
HIGH     IAM-PRINCIPAL-STAR         queue.json: Open (#1)
         Principal "*" with no Condition makes this statement public to everyone
         fix: Name the intended principals, or add a Condition such as aws:PrincipalOrgID, aws:SourceVpce, aws:SourceArn/aws:SourceAccount (for AWS services)
CRITICAL IAM-TRUST-WILDCARD         trust.json: #1
         trust policy principal * allows anyone on the internet with AWS credentials to assume this role
         fix: Name the exact role/account ARNs in Principal; for cross-account add sts:ExternalId or aws:PrincipalOrgID
iamlint: 9 finding(s)
```

## Usage

```bash
iamlint policy.json                      # one or more files
cat policy.json | iamlint                # stdin
iamlint *.json --fail-on high            # only HIGH and CRITICAL fail
iamlint policy.json --ignore IAM-RESOURCE-STAR
iamlint policy.json --json
```

It accepts a bare policy document or a wrapper from the AWS CLI (`get-role`, `get-policy-version`, SQS `Attributes.Policy`, KMS `KeyPolicy`),
`Statement` as an object or a list, and `Action`/`Resource` as a string or a list.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `IAM-ACTION-STAR` | HIGH / CRITICAL | Allow with `Action: "*"` (CRITICAL with `Resource: "*"`) |
| `IAM-SERVICE-WILDCARD` | MEDIUM / HIGH | Allow with `service:*` |
| `IAM-S3-STAR` | HIGH | `s3:*` (bucket deletion, policy changes, all reads) |
| `IAM-RESOURCE-STAR` | LOW / MEDIUM | Allow on `Resource: "*"` (LOW for describe/list only) |
| `IAM-NOTACTION-ALLOW`, `IAM-NOTRESOURCE-ALLOW`, `IAM-NOTPRINCIPAL-ALLOW` | HIGH | Allow combined with a Not* element |
| `IAM-PRINCIPAL-STAR` | HIGH | `Principal: "*"` with no Condition |
| `IAM-PRINCIPAL-STAR-WEAKCOND` | MEDIUM | public principal whose Condition does not restrict the caller |
| `IAM-TRUST-WILDCARD` | HIGH / CRITICAL | wildcard in a trust policy principal |
| `IAM-PASSROLE-STAR` | HIGH | `iam:PassRole` on `*` without `iam:PassedToService` |
| `IAM-PRIVESC` | MEDIUM / HIGH | single actions that can raise privileges (`iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `sts:AssumeRole` on `*`, ...) |
| `IAM-PRIVESC-COMBO` | HIGH | `iam:PassRole` on `*` plus a service action (Lambda, EC2, CloudFormation, Glue, ECS, SageMaker, Data Pipeline) that can run code under another role |
| `IAM-EXFIL-STAR` | MEDIUM / HIGH | data-reading or data-sharing actions on `*` (`secretsmanager:GetSecretValue`, `kms:Decrypt`, `ec2:ModifySnapshotAttribute`, ...) |
| `IAM-VERSION` | LOW / MEDIUM | missing or old (`2008-10-17`) Version |
| `IAM-DUP-SID` | MEDIUM | duplicate Sids |
| `IAM-SERVICE-NO-SOURCE` | LOW | service principal without `aws:SourceArn`/`aws:SourceAccount` |
| `IAM-MALFORMED` | MEDIUM | non-object statements, bad Effect, non-string actions, no statements |

Exit codes: `0` clean (at or above `--fail-on`, default `low`), `1` findings, `2` usage or input error (bad JSON, no `Statement`, not a regular file,
over 5 MiB, unreadable). Any input error makes the whole run exit `2`.

## Limits

- It does lexical analysis of one document. It does not evaluate IAM like AWS does: no SCPs, permission boundaries, session policies, resource policies
  on the other side of a request, or Deny statements that offset an Allow.
- Combination checks (`IAM-PRIVESC-COMBO`) combine Allow statements inside one document only; a principal's permissions spread over several attached
  policies are not joined. Conditions on Allow statements are not weighed except for the public-principal checks.
- The privilege-escalation, exfiltration and service-wildcard lists are curated, not exhaustive, and new AWS actions will not be in them.
- Cross-account trust to a specific account is not judged (for example a missing `sts:ExternalId`).
- Policy variables, NotAction subtleties and `aws:*` condition operator semantics are only approximated.
- Findings are leads to review; some (for example `Resource: "*"` for services that require it) are legitimate.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [apispec-lint](https://github.com/TPOALOS/apispec-lint) · [zonelint](https://github.com/TPOALOS/zonelint) · [planguard](https://github.com/TPOALOS/planguard) · [all 61 tools](https://tpoalos.github.io)
