# Changelog

## 1.0.0

First release.

- Lints IAM, trust, S3, KMS and SQS policy JSON from files or stdin, fully offline
- Wildcard actions/resources, Not* elements, public principals, PassRole, privilege-escalation actions and combinations, exfiltration-prone actions, version and Sid checks
- A concrete fix for every finding; `--json`, `--fail-on`, `--ignore`
