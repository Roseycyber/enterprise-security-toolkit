#!/usr/bin/env python3
"""
SIEM Anomaly Detector

Parses an authentication log export (CSV) and flags three patterns,
representative of first-pass SIEM correlation rules feeding a SOAR
playbook (see docs/06-siem-soar-integration.md):

  1. Brute force        - >= BRUTE_FORCE_THRESHOLD failed logins for the
                           same user within BRUTE_FORCE_WINDOW_MIN minutes.
  2. Impossible travel   - successful logins for the same user from two
                           different locations too close together in time
                           to be legitimate travel.
  3. After-hours privileged access - privileged=true logins outside
                           business hours (BUSINESS_HOURS_START/END, local).

Expected CSV columns:
    timestamp (ISO 8601), user, source_ip, location, result (success/failure),
    privileged (true/false)

Usage:
    python3 siem_anomaly_detector.py <path_to_auth_logs.csv>
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MIN = 10

# Rough average commercial flight speed, used to sanity-check whether two
# logins from different locations could plausibly be the same traveling user.
MIN_PLAUSIBLE_MINUTES_PER_KM = 60 / 900  # ~900 km/h cruising speed

BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 19

# Minimal illustrative distance table between sample cities (km), symmetric.
# In a real deployment this would be a geolocation lookup (e.g. IP geo DB).
CITY_DISTANCES_KM = {
    frozenset(["New York", "London"]): 5570,
    frozenset(["New York", "Chicago"]): 1145,
    frozenset(["London", "Singapore"]): 10850,
    frozenset(["Chicago", "Chicago"]): 0,
    frozenset(["New York", "New York"]): 0,
}


def parse_time(ts):
    return datetime.fromisoformat(ts)


def str_to_bool(value):
    return str(value).strip().lower() in ("true", "1", "yes", "y")


def distance_km(loc_a, loc_b):
    if loc_a == loc_b:
        return 0
    return CITY_DISTANCES_KM.get(frozenset([loc_a, loc_b]), 8000)  # default: assume far apart


def detect_brute_force(events_by_user):
    findings = []
    for user, events in events_by_user.items():
        failures = sorted(
            [e for e in events if e["result"] == "failure"],
            key=lambda e: e["timestamp"],
        )
        for i in range(len(failures)):
            window_start = failures[i]["timestamp"]
            count = 1
            for j in range(i + 1, len(failures)):
                gap_minutes = (failures[j]["timestamp"] - window_start).total_seconds() / 60
                if gap_minutes <= BRUTE_FORCE_WINDOW_MIN:
                    count += 1
                else:
                    break
            if count >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "severity": "High",
                    "user": user,
                    "finding": (
                        f"{count} failed logins within {BRUTE_FORCE_WINDOW_MIN} minutes "
                        f"starting {window_start.isoformat()}"
                    ),
                })
                break  # one finding per user is enough for this demo
    return findings


def detect_impossible_travel(events_by_user):
    findings = []
    for user, events in events_by_user.items():
        successes = sorted(
            [e for e in events if e["result"] == "success"],
            key=lambda e: e["timestamp"],
        )
        for i in range(len(successes) - 1):
            a, b = successes[i], successes[i + 1]
            if a["location"] == b["location"]:
                continue
            gap_minutes = (b["timestamp"] - a["timestamp"]).total_seconds() / 60
            dist = distance_km(a["location"], b["location"])
            min_required_minutes = dist * MIN_PLAUSIBLE_MINUTES_PER_KM
            if gap_minutes < min_required_minutes:
                findings.append({
                    "severity": "Critical",
                    "user": user,
                    "finding": (
                        f"Login from {a['location']} at {a['timestamp'].isoformat()} then "
                        f"{b['location']} at {b['timestamp'].isoformat()} "
                        f"({gap_minutes:.0f} min apart, ~{dist} km) — not plausible travel time"
                    ),
                })
    return findings


def detect_afterhours_privileged(events_by_user):
    findings = []
    for user, events in events_by_user.items():
        for e in events:
            if e["result"] == "success" and e["privileged"]:
                hour = e["timestamp"].hour
                if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                    findings.append({
                        "severity": "Medium",
                        "user": user,
                        "finding": (
                            f"Privileged access at {e['timestamp'].isoformat()} "
                            f"(outside {BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00 business hours)"
                        ),
                    })
    return findings


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_auth_logs.csv>")
        sys.exit(1)

    events_by_user = defaultdict(list)
    with open(sys.argv[1], newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events_by_user[row["user"]].append({
                "timestamp": parse_time(row["timestamp"]),
                "source_ip": row["source_ip"],
                "location": row["location"],
                "result": row["result"].strip().lower(),
                "privileged": str_to_bool(row.get("privileged", "false")),
            })

    all_findings = []
    all_findings.extend(detect_brute_force(events_by_user))
    all_findings.extend(detect_impossible_travel(events_by_user))
    all_findings.extend(detect_afterhours_privileged(events_by_user))
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    print("=" * 80)
    print("SIEM ANOMALY DETECTOR — FINDINGS")
    print("=" * 80)
    if not all_findings:
        print("No anomalies detected.")
        return

    for f in all_findings:
        print(f"\n[{f['severity']}] User: {f['user']}")
        print(f"  -> {f['finding']}")

    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\n" + "-" * 80)
    print("Summary:", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))))


if __name__ == "__main__":
    main()
