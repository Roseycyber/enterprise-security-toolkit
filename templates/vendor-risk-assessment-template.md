# Vendor Risk Assessment

**Vendor name:**
**Business owner / requester:**
**Date of assessment:**
**Assessor:**

## 1. Engagement summary
- What service does this vendor provide?
- What data will they access or store? (classification: public / internal / confidential / restricted)
- What system access will they have? (none / read-only / read-write / admin)
- Is this vendor customer-facing or purely internal?

## 2. Tiering (see docs/04-third-party-risk-management.md)
- [ ] Tier 1 — restricted data or admin access
- [ ] Tier 2 — confidential data, read-write access
- [ ] Tier 3 — internal data only, no system access

## 3. Security posture evidence
- SOC 2 Type II report on file? Date of report: __________
- ISO 27001 certificate on file? Expiry: __________
- Penetration test summary provided? Date: __________
- Subprocessor list reviewed? Any subprocessors in restricted jurisdictions?

## 4. Technical controls confirmed
- [ ] Data encrypted in transit (TLS 1.2+)
- [ ] Data encrypted at rest
- [ ] MFA enforced for vendor personnel accessing our systems/data
- [ ] Documented breach notification SLA (target: within 72 hours)
- [ ] Data deletion / return process defined for contract termination

## 5. Risk scoring
Using the 1–5 x 1–5 matrix from doc 01:

- Likelihood: ____ (based on vendor's security maturity and access level)
- Impact: ____ (based on data classification and business criticality)
- **Risk score: ____ / 25**
- Risk tier: Low / Medium / High / Critical

## 6. Decision
- [ ] Approved as-is
- [ ] Approved with conditions (list below)
- [ ] Not approved

**Conditions / required remediations before go-live:**

## 7. Ongoing monitoring plan
- Reassessment date: __________
- Continuous monitoring method (e.g. security rating service): __________
