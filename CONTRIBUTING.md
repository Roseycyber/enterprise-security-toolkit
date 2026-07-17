# Contributing to the Enterprise Security & IAM Assessment Toolkit

Thank you for your interest in contributing! This project is a practical,
educational toolkit for enterprise security risk assessment, IAM analysis,
threat modeling, vulnerability triage, and SIEM/SOAR-style detection. Whether
you're fixing a typo, adding a detection pattern, or mapping a new framework,
contributions of every size are welcome — including from first-time contributors.

## Ways to contribute

- **Improve the tools** — add detection patterns to the IAM analyzer, the
  vulnerability triage helper, or the SIEM anomaly detector.
- **Add framework mappings** — map findings to additional standards (CIS
  Controls, SOC 2, etc.).
- **Improve documentation** — clarify a doc, add a diagram, fix wording.
- **Add sample data** — realistic (but synthetic) test cases make the tools
  more useful.
- **Report bugs or suggest ideas** — open an issue describing what you found or
  what you'd like to see.

## Good first issues

If you're new, look for issues labelled **`good first issue`** — these are
small, self-contained, and don't require understanding the whole codebase.
Issues labelled **`help wanted`** are slightly larger and great if you have some
GRC or security background.

## How to contribute (step by step)

1. **Comment on the issue** you'd like to work on, so we don't duplicate effort.
   If there's no issue yet, open one first to discuss the idea.
2. **Fork the repository** (the "Fork" button, top right of the repo page).
3. **Create a branch** for your change (e.g. `add-s3-wildcard-check`).
4. **Make your change.** Keep it focused — one logical change per pull request.
5. **Test it.** Make sure the tools still run against the sample data:
   ```bash
   python3 tools/iam_policy_analyzer.py sample-data/iam_policies.json
   python3 tools/vuln_triage_helper.py sample-data/vuln_scan_export.csv
   python3 tools/siem_anomaly_detector.py sample-data/auth_logs.csv
   ```
6. **Open a pull request** with a clear title and a short description of what you
   changed and why. Reference the issue number (e.g. "Closes #3").

## Guidelines

- **Keep it defensive and ethical.** This is a defensive security education
  project. Contributions must not add offensive tooling or anything designed to
  attack systems without authorisation.
- **No real data, ever.** All sample data must be synthetic. Never commit real
  credentials, logs, IP addresses, or personal data.
- **Cite sources** for any framework mappings (link the official standard).
- **Plain, standard-library Python** where possible, so the tools run anywhere
  without extra installs.
- **Be clear over clever.** Readable code and docs matter more than compactness
  here — this is a learning-focused project.

## Questions

Not sure where to start, or want feedback on an idea before you build it? Open
an issue and ask. No question is too basic — helping people learn is part of the
point of this project.

By contributing, you agree that your contributions will be licensed under the
same [MIT License](LICENSE) that covers this project.
