# Enterprise Security Risk & IAM Assessment Toolkit

A portfolio project demonstrating applied enterprise security skills: risk
assessment methodology, IAM security modeling, threat modeling, vulnerability
triage, and SIEM/SOAR-style detection — built around a hybrid on-prem +
cloud enterprise environment.

## Why this repo exists

This project was built to demonstrate hands-on capability against a common
security-role skillset:

| Job requirement | Where it's covered |
|---|---|
| Risk assessment methodologies (NIST, ISO 27001) | [`docs/01-risk-assessment-framework.md`](docs/01-risk-assessment-framework.md) |
| AWS Well-Architected Framework | [`docs/01-risk-assessment-framework.md`](docs/01-risk-assessment-framework.md#aws-well-architected-mapping) |
| IAM security model | [`docs/02-iam-security-model.md`](docs/02-iam-security-model.md), [`tools/iam_policy_analyzer.py`](tools/iam_policy_analyzer.py) |
| Threat modeling | [`docs/03-threat-modeling.md`](docs/03-threat-modeling.md), [`templates/threat-model-template.md`](templates/threat-model-template.md) |
| Vulnerability & pen-test oversight ("which fires are real") | [`docs/05-vulnerability-management-process.md`](docs/05-vulnerability-management-process.md), [`tools/vuln_triage_helper.py`](tools/vuln_triage_helper.py) |
| Third-party risk management (owning the process) | [`docs/04-third-party-risk-management.md`](docs/04-third-party-risk-management.md), [`templates/vendor-risk-assessment-template.md`](templates/vendor-risk-assessment-template.md) |
| SIEM / SOAR / IT security operations | [`docs/06-siem-soar-integration.md`](docs/06-siem-soar-integration.md), [`tools/siem_anomaly_detector.py`](tools/siem_anomaly_detector.py) |
| AI experience / AI governance | [`docs/07-ai-governance-iso42001.md`](docs/07-ai-governance-iso42001.md) — ISO 42001 + NIST AI RMF applied |
| Enterprise risk & compliance frameworks | [`templates/risk-register-template.csv`](templates/risk-register-template.csv) |

## Repo structure

```
enterprise-security-toolkit/
├── docs/            written frameworks, mapped to NIST CSF / ISO 27001 / AWS WAF
├── templates/       reusable risk register, vendor assessment, threat model docs
├── tools/           three runnable Python tools (see below)
├── sample-data/     synthetic data to run the tools against out of the box
└── .gitignore
```

## The three tools

**Prerequisites:** Python 3.8 or newer. No packages to install — the tools
use only the Python standard library, so they run anywhere Python runs.

All three run standalone, no cloud credentials required — they operate on
sample/exported data, the way a security analyst would work from an export
rather than live API calls in a portfolio context.

### 1. IAM Policy Analyzer
```bash
python3 tools/iam_policy_analyzer.py sample-data/iam_policies.json
```
Flags wildcard actions/resources, missing MFA conditions, and known
privilege-escalation patterns (e.g. `iam:PassRole` + `ec2:RunInstances`) in
AWS-style IAM policy documents. Outputs a risk-ranked findings list.

### 2. Vulnerability Triage Helper
```bash
python3 tools/vuln_triage_helper.py sample-data/vuln_scan_export.csv
```
Takes a Nessus/Qualys-style scan export and re-ranks findings using a
composite score: CVSS base score, asset criticality tier, and known
exploit availability — the "which fires are real" logic. Demonstrates
triage judgment, not just re-printing scanner output.

### 3. SIEM Anomaly Detector
```bash
python3 tools/siem_anomaly_detector.py sample-data/auth_logs.csv
```
Parses authentication logs and flags: brute-force patterns, impossible
travel (same user, two geographies, too little time between them),
and after-hours privileged access. Simple statistical scoring — the
kind of first-pass detection logic that feeds a SOAR playbook.

## Frameworks referenced

- NIST Cybersecurity Framework (CSF) 2.0
- NIST SP 800-30 (Risk Assessment)
- NIST AI Risk Management Framework (AI RMF 1.0)
- ISO/IEC 27001:2022
- ISO/IEC 42001:2023 (AI Management Systems)
- AWS Well-Architected Framework — Security Pillar
- MITRE ATT&CK (referenced in threat modeling)
- STRIDE threat modeling methodology

## About the author

I'm **Ese Rose Idjogbe**, a CompTIA Security+ certified Governance, Risk &
Compliance professional based in Sheffield, UK, focused on the intersection
of information-security risk and AI governance. I've delivered ISO
27001-aligned risk assessments, third-party/supplier risk reviews, and
audit-evidence programmes in regulated environments — including closing
100% of outstanding audit-evidence requests on schedule during a recent GRC
placement. I have hands-on training in **ISO 42001 (AI Management Systems)**
alongside ISO 27001, which is where I'm concentrating my work — and this
repository is part of that: the hands-on side of GRC.

**Background:** MSc, Sheffield Hallam University · CompTIA Security+ ·
Microsoft Azure Fundamentals (AZ-900) · ISO 27001 & ISO 42001 (trained) ·
structured cybersecurity apprenticeship.

💼 LinkedIn: https://www.linkedin.com/in/eseidjogbe/ · 📫 eserosep.venture@gmail.com

## Disclaimer

All data in `sample-data/` is synthetic and generated for demonstration
purposes. No real systems, credentials, or logs are included.
