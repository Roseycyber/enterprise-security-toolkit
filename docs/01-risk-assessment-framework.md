# Risk Assessment Framework

## Purpose

Defines the methodology used to identify, analyze, and prioritize security
risk across the enterprise (on-prem + cloud), and how it maps to recognized
standards so findings translate cleanly into audit and compliance language.

## Methodology

We use a hybrid approach built on **NIST SP 800-30** for the risk process
itself, with **ISO/IEC 27001** as the control-catalog and management-system
layer, and the **AWS Well-Architected Framework Security Pillar** for
cloud-specific technical controls.

### Risk assessment steps (NIST SP 800-30 aligned)

1. **Prepare** — define scope, assumptions, risk tolerance, and stakeholders.
2. **Identify threat sources and events** — internal, external, adversarial
   and non-adversarial (e.g. misconfiguration, natural disaster).
3. **Identify vulnerabilities and predisposing conditions** — technical
   (unpatched systems, over-permissive IAM) and procedural (no vendor
   offboarding process).
4. **Determine likelihood** — using a 1–5 scale informed by threat
   intelligence, exposure, and historical incident data.
5. **Determine impact** — confidentiality, integrity, availability, plus
   business impact (financial, regulatory, reputational).
6. **Determine risk** — likelihood × impact, plotted on a 5x5 heat map.
7. **Communicate and maintain** — risk register updated continuously,
   reviewed quarterly with risk owners.

### NIST CSF 2.0 function mapping

| CSF Function | How it's applied here |
|---|---|
| Govern | Risk register ownership, quarterly risk committee review |
| Identify | Asset inventory, this risk assessment process |
| Protect | IAM model (doc 02), access control standards |
| Detect | SIEM/SOAR pipeline (doc 06) |
| Respond | Incident response playbooks, tied to SOAR |
| Recover | Backup/DR testing (out of scope for this repo, referenced only) |

### ISO/IEC 27001:2022 mapping (selected Annex A controls)

| Annex A control | Relevance |
|---|---|
| A.5.7 Threat intelligence | Feeds likelihood scoring |
| A.5.19–5.23 Supplier relationships | See doc 04, third-party risk |
| A.8.2 Privileged access rights | See doc 02, IAM model |
| A.8.9 Configuration management | Vulnerability management process, doc 05 |
| A.8.16 Monitoring activities | SIEM/SOAR, doc 06 |

## AWS Well-Architected mapping

The AWS Well-Architected Framework's Security Pillar organizes controls into
seven areas. This project addresses:

| WAF Security area | Coverage |
|---|---|
| Identity & Access Management | `tools/iam_policy_analyzer.py`, doc 02 |
| Detection | `tools/siem_anomaly_detector.py`, doc 06 |
| Infrastructure Protection | referenced in threat model (doc 03) |
| Data Protection | referenced, not the focus of this repo |
| Incident Response | doc 06, SOAR playbook pattern |

## Risk scoring model used across this repo

A 1–5 likelihood x 1–5 impact matrix, producing a risk score of 1–25:

- **1–6**: Low — track in register, no immediate action
- **7–12**: Medium — remediate within a defined SLA (e.g. 90 days)
- **13–19**: High — remediate within a shorter SLA (e.g. 30 days), escalate to risk owner
- **20–25**: Critical — immediate action, executive visibility

This same scoring logic is what `tools/vuln_triage_helper.py` automates for
vulnerability scan findings specifically.

## Output

All findings from this process feed the central risk register:
[`templates/risk-register-template.csv`](../templates/risk-register-template.csv)
