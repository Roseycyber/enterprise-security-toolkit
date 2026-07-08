# Threat Modeling

## Methodology

STRIDE, applied at the design-review stage of any new business project —
this is the practical version of "you'll be the person people come to
when they want to know whether their bright idea is secure."

STRIDE categories:

- **S**poofing — impersonating a user, system, or identity
- **T**ampering — unauthorized modification of data or code
- **R**epudiation — inability to prove an action occurred (or didn't)
- **I**nformation disclosure — exposure of data to unauthorized parties
- **D**enial of service — availability impact
- **E**levation of privilege — gaining higher access than granted

## Worked example: new internal tool requesting AWS access

**Scenario**: A team wants to build an internal dashboard that reads
customer data from an RDS database and posts summaries to Slack, running
on an EC2 instance with an attached IAM role.

### Data flow (simplified)

```
[Analyst] -> [Dashboard app on EC2] -> [RDS: customer data]
                    |
                    v
              [Slack webhook]
```

### STRIDE analysis

| Category | Threat identified | Mitigation |
|---|---|---|
| Spoofing | Compromised EC2 instance role credentials used to impersonate the app elsewhere in the account | Scope the IAM role narrowly (permission boundary), no wildcard resources |
| Tampering | Dashboard code modified via an unpatched dependency to alter reported figures | Dependency scanning in CI, signed deployment artifacts |
| Repudiation | No audit trail of who queried what customer data | Enable RDS audit logging + CloudTrail on the IAM role's activity |
| Information disclosure | Slack webhook posts customer PII into a channel with broad membership | Data classification review before the webhook is approved; strip PII from payload |
| Denial of service | Dashboard query pattern accidentally overloads production RDS | Point the tool at a read replica, not primary |
| Elevation of privilege | EC2 role has `iam:PassRole`, allowing the app (if compromised) to launch new privileged resources | Remove `iam:PassRole` from the role; it isn't needed for the stated function |

### Outcome

This is the kind of review that turns "can we ship this" into a short,
specific list of required changes — rather than a blanket yes/no. The
elevation-of-privilege finding above is exactly the pattern
`tools/iam_policy_analyzer.py` is built to catch automatically.

## Template

Use [`templates/threat-model-template.md`](../templates/threat-model-template.md)
for new reviews.
