# Third-Party Risk Management (TPRM)

## Ownership

This process is owned end-to-end by security — from intake through
ongoing monitoring — not merely advised on. Business teams engage
security *before* signing, not after.

## Process

### 1. Intake
Any new vendor handling company data, connecting to internal systems, or
providing a critical business function is registered before contract
signature. No exceptions for "just a quick trial."

### 2. Tiering
Vendors are tiered by inherent risk, based on:
- Data classification handled (public / internal / confidential / restricted)
- System access level (none / read-only / read-write / admin)
- Business criticality (would an outage stop revenue-generating operations?)

| Tier | Criteria | Assessment depth |
|---|---|---|
| Tier 1 | Restricted data or admin-level system access | Full assessment: security questionnaire, SOC 2/ISO 27001 evidence review, architecture review |
| Tier 2 | Confidential data, read-write access | Standard questionnaire + evidence review |
| Tier 3 | Internal data only, no system access | Lightweight questionnaire |

### 3. Assessment
Using [`templates/vendor-risk-assessment-template.md`](../templates/vendor-risk-assessment-template.md):
- Review vendor's SOC 2 Type II / ISO 27001 certificate, or equivalent.
- Validate encryption in transit/at rest, breach notification terms,
  subprocessor list, and data residency.
- Map findings to the same 1–25 risk score used elsewhere in this repo
  (see doc 01) so third-party risk sits in the same register as internal risk.

### 4. Contractual controls
Security requirements (breach notification SLA, right-to-audit,
data deletion on termination) are contract terms, not best-effort asks —
coordinated with legal/procurement, with security holding the pen on the
security exhibit/addendum.

### 5. Ongoing monitoring
- Tier 1 vendors: annual full reassessment, plus continuous monitoring
  (e.g. security rating services, breach disclosure feeds).
- Tier 2/3: reassessed on contract renewal or material change in scope.
- Any vendor security incident triggers immediate reassessment
  regardless of tier or schedule.

### 6. Offboarding
Access revoked and data deletion confirmed in writing before a vendor
relationship is closed — tracked as an open item in the risk register
until confirmed, not assumed complete at contract end.

## Why this sits with security, not procurement

Procurement optimizes for cost and delivery. Security is the only party
incentivized to say no to a bad control posture regardless of price —
that's the "own it" distinction from "support it."
