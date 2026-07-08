#!/usr/bin/env python3
"""
IAM Policy Analyzer

Scans AWS-style IAM policy documents (JSON) for common over-permissive
and privilege-escalation patterns, and produces a risk-ranked findings
report.

Usage:
    python3 iam_policy_analyzer.py <path_to_policies.json>

Input format: a JSON file containing a list of policy objects, each with
a "PolicyName" and a "Document" (standard IAM policy document structure).
See sample-data/iam_policies.json for an example.

This is a static-analysis tool for portfolio/demo purposes: it evaluates
policy documents you provide, it does not connect to any live AWS account.
"""

import json
import sys

# Actions that, combined with iam:PassRole, are classic privilege-escalation
# paths (the resulting principal can hand its own permissions to a new
# compute resource running under a different, possibly more privileged, role).
ESCALATION_COMPANION_ACTIONS = {
    "ec2:runinstances",
    "lambda:createfunction",
    "lambda:invokefunction",
    "ecs:runtask",
    "cloudformation:createstack",
}

SELF_ESCALATION_ACTIONS = {
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:putgrouppolicy",
    "iam:createaccesskey",
}

SENSITIVE_ACTIONS_REQUIRING_MFA = {
    "iam:*",
    "iam:deleteuser",
    "iam:deleterole",
    "s3:deletebucket",
    "ec2:terminateinstances",
}


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_actions(actions):
    return {a.lower() for a in as_list(actions)}


def has_mfa_condition(statement):
    conditions = statement.get("Condition", {})
    for cond_operator, cond_map in conditions.items():
        for cond_key in cond_map:
            key_lower = cond_key.lower()
            if "multifactorauthage" in key_lower or "multifactorauthpresent" in key_lower:
                return True
    return False


def analyze_statement(policy_name, statement):
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_actions(statement.get("Action"))
    resources = as_list(statement.get("Resource"))

    # Wildcard action
    if "*" in actions:
        findings.append({
            "severity": "Critical",
            "policy": policy_name,
            "finding": "Statement allows all actions ('Action': '*')",
        })

    # Wildcard resource
    if "*" in resources:
        findings.append({
            "severity": "High",
            "policy": policy_name,
            "finding": "Statement applies to all resources ('Resource': '*')",
        })

    # Privilege escalation: PassRole + compute launch capability in same policy
    if "iam:passrole" in actions and actions & ESCALATION_COMPANION_ACTIONS:
        findings.append({
            "severity": "Critical",
            "policy": policy_name,
            "finding": (
                "iam:PassRole combined with a compute-launch action "
                f"({', '.join(sorted(actions & ESCALATION_COMPANION_ACTIONS))}) "
                "allows privilege escalation to any role passed in"
            ),
        })

    # Self privilege escalation actions
    matched_self_escalation = actions & SELF_ESCALATION_ACTIONS
    if matched_self_escalation:
        findings.append({
            "severity": "High",
            "policy": policy_name,
            "finding": (
                "Statement grants self privilege-escalation capable actions: "
                f"{', '.join(sorted(matched_self_escalation))}"
            ),
        })

    # Sensitive action without MFA condition
    sensitive_hit = actions & SENSITIVE_ACTIONS_REQUIRING_MFA
    if sensitive_hit and not has_mfa_condition(statement):
        findings.append({
            "severity": "Medium",
            "policy": policy_name,
            "finding": (
                f"Sensitive action(s) {', '.join(sorted(sensitive_hit))} "
                "granted without an MFA condition"
            ),
        })

    return findings


def analyze_trust_policy(policy_name, document):
    findings = []
    for statement in as_list(document.get("Statement")):
        principal = statement.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            findings.append({
                "severity": "Critical",
                "policy": policy_name,
                "finding": "Trust policy allows any AWS principal ('Principal': '*') to assume this role",
            })
    return findings


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_policies.json>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        policies = json.load(f)

    all_findings = []
    for policy in policies:
        name = policy.get("PolicyName", "UNNAMED_POLICY")
        document = policy.get("Document", {})

        if policy.get("Type") == "TrustPolicy":
            all_findings.extend(analyze_trust_policy(name, document))
            continue

        for statement in as_list(document.get("Statement")):
            all_findings.extend(analyze_statement(name, statement))

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    print("=" * 70)
    print("IAM POLICY ANALYZER — FINDINGS REPORT")
    print("=" * 70)
    if not all_findings:
        print("No risky patterns detected in the provided policies.")
        return

    for f in all_findings:
        print(f"\n[{f['severity']}] Policy: {f['policy']}")
        print(f"  -> {f['finding']}")

    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\n" + "-" * 70)
    print("Summary:", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))))


if __name__ == "__main__":
    main()
