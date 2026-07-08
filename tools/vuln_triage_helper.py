#!/usr/bin/env python3
"""
Vulnerability Triage Helper

Takes a vulnerability scanner export (CSV, Nessus/Qualys-style columns)
and re-ranks findings by a composite risk score rather than raw CVSS
alone — the "which fires are real" logic described in doc
05-vulnerability-management-process.md.

Composite score formula (0-25 scale, matches the risk register scale in
docs/01-risk-assessment-framework.md):

    composite = round(
        (cvss_score / 10) * 5 * 0.5          # severity component (max 12.5 -> scaled to 5)
      + asset_criticality * 1.0              # 1-5 scale, direct input
      + (2.5 if exploit_available else 0)    # exploit availability bump
    )

Simplified in code as a weighted sum, clipped to 1-25 and mapped to the
same Low/Medium/High/Critical tiers used across the repo.

Expected CSV columns:
    finding_id, host, description, cvss_score, asset_criticality (1-5),
    exploit_available (true/false), internet_facing (true/false)

Usage:
    python3 vuln_triage_helper.py <path_to_scan_export.csv>
"""

import csv
import sys


def str_to_bool(value):
    return str(value).strip().lower() in ("true", "1", "yes", "y")


def composite_score(cvss_score, asset_criticality, exploit_available, internet_facing):
    severity_component = (cvss_score / 10) * 12.5  # max 12.5 points
    criticality_component = asset_criticality * 2.0  # max 10 points
    exploit_component = 2.5 if exploit_available else 0
    exposure_component = 1.0 if internet_facing else 0  # small nudge, not double-counted heavily

    raw = severity_component + criticality_component + exploit_component + exposure_component
    # normalize roughly onto a 1-25 scale
    score = round(raw * (25 / 28.0))
    return max(1, min(25, score))


def tier_for_score(score):
    if score >= 20:
        return "Critical"
    if score >= 13:
        return "High"
    if score >= 7:
        return "Medium"
    return "Low"


SLA_DAYS = {"Critical": 3, "High": 30, "Medium": 90, "Low": 180}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_scan_export.csv>")
        sys.exit(1)

    rows = []
    with open(sys.argv[1], newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cvss = float(row["cvss_score"])
            criticality = int(row["asset_criticality"])
            exploit = str_to_bool(row.get("exploit_available", "false"))
            internet_facing = str_to_bool(row.get("internet_facing", "false"))

            score = composite_score(cvss, criticality, exploit, internet_facing)
            tier = tier_for_score(score)

            rows.append({
                **row,
                "composite_score": score,
                "risk_tier": tier,
                "remediation_sla_days": SLA_DAYS[tier],
            })

    rows.sort(key=lambda r: r["composite_score"], reverse=True)

    print("=" * 90)
    print("VULNERABILITY TRIAGE — RISK-RANKED FINDINGS")
    print("=" * 90)
    header = f"{'ID':<10}{'Host':<20}{'CVSS':<6}{'Score':<7}{'Tier':<10}{'SLA (days)':<12}Description"
    print(header)
    print("-" * 90)
    for r in rows:
        print(
            f"{r['finding_id']:<10}{r['host']:<20}{r['cvss_score']:<6}"
            f"{r['composite_score']:<7}{r['risk_tier']:<10}{r['remediation_sla_days']:<12}"
            f"{r['description'][:40]}"
        )

    counts = {}
    for r in rows:
        counts[r["risk_tier"]] = counts.get(r["risk_tier"], 0) + 1
    print("\n" + "-" * 90)
    print("Summary:", ", ".join(f"{t}: {counts.get(t, 0)}" for t in ["Critical", "High", "Medium", "Low"]))
    print(
        "\nNote: raw CVSS ranking would order these differently — this composite "
        "score is what determines the actual remediation queue, weighting asset "
        "criticality and real-world exploit availability alongside severity."
    )


if __name__ == "__main__":
    main()
