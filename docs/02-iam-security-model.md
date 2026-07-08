# Identity & Access Management (IAM) Security Model

## Scope

Covers identity governance across a hybrid environment: on-prem Active
Directory (workforce identity) and AWS IAM (cloud workload/resource
identity), with a shared set of principles.

## Core principles

1. **Least privilege by default** — access starts at zero, grows through
   justified, time-bound requests, not the reverse.
2. **Role-based access control (RBAC) as the primary model**, with
   attribute-based (ABAC) conditions layered on for cloud resources
   (e.g. tag-based resource scoping in AWS IAM).
3. **Separation of duties** — no single identity can both request and
   approve its own privilege escalation (e.g. the same person cannot
   create an IAM policy and attach it to themselves).
4. **Just-in-time (JIT) privileged access** — standing admin access is
   the exception, not the default. Privileged roles are assumed for a
   bounded session and logged.
5. **MFA enforced at the identity provider**, and required as a policy
   condition for any sensitive AWS action (documented in the analyzer
   tool's rule set).
6. **Joiner-Mover-Leaver (JML) process** — access is tied to HR lifecycle
   events, not manual tickets alone. Leavers are deprovisioned same-day.

## On-prem AD model

- Tiered administration (Tier 0 / 1 / 2) to prevent workstation compromise
  from escalating to domain admin.
- Privileged Access Workstations (PAWs) for Tier 0 administration.
- Group Policy enforces password/lockout policy aligned to NIST 800-63B
  guidance (length over complexity, breached-password screening).

## AWS IAM model

- No long-lived access keys for human users; federated SSO into roles.
- Service-linked and workload identities use short-lived credentials
  (STS) wherever possible.
- Permission boundaries applied to any role capable of creating other
  IAM entities, to cap privilege escalation blast radius.
- SCPs (Service Control Policies) at the AWS Organization level as a
  guardrail layer above individual account IAM policies.

## Common IAM risk patterns this model defends against

These are the specific patterns `tools/iam_policy_analyzer.py` scans for:

| Pattern | Why it matters |
|---|---|
| `"Action": "*"` or `"Resource": "*"` | Removes least-privilege boundary entirely |
| Missing MFA condition on sensitive actions | Static-credential compromise = full access |
| `iam:PassRole` + compute-launch permissions together | Classic privilege-escalation path to any role in the account |
| `iam:CreatePolicyVersion` / `iam:AttachUserPolicy` without restriction | Allows self privilege-escalation |
| Trust policies with wildcard principals | Allows any AWS account to assume the role |

## Access review cadence

- Privileged access: reviewed monthly.
- Standard user access: reviewed quarterly.
- Service accounts / third-party integrations: reviewed quarterly and
  on any vendor risk tier change (see doc 04).
