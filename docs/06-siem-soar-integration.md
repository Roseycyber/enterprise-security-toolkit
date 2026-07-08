# SIEM / SOAR / IT Security Operations

## Pipeline overview

```
[Log sources] -> [SIEM: aggregation + correlation] -> [Detection rules]
                                                            |
                                                            v
                                            [SOAR: automated response playbooks]
                                                            |
                                                            v
                                                [Analyst review / escalation]
```

## Log sources feeding the SIEM

- Identity provider / AD authentication logs
- AWS CloudTrail (control-plane API activity)
- VPC Flow Logs / firewall logs
- Endpoint detection and response (EDR) telemetry
- Application logs from Tier 1 business systems

## Detection logic (what this repo demonstrates)

`tools/siem_anomaly_detector.py` implements three first-pass detection
rules, representative of the kind of logic a SIEM correlation rule or
detection-as-code pipeline would run:

1. **Brute force** — N failed authentications for the same account within
   a rolling window, from one or more source IPs.
2. **Impossible travel** — successful logins for the same account from two
   geographically distant locations within a time gap too short for
   legitimate travel.
3. **After-hours privileged access** — privileged role usage outside
   defined business hours, which is disproportionately likely to be either
   automation that should be documented or something worth a second look.

These are intentionally simple, explainable rules — the right first layer
before adding a statistical/ML anomaly-scoring layer on top, which is the
direction most enterprise SIEM tooling has moved (UEBA - user & entity
behavior analytics). The scoring approach in the script is written so it
could be extended with a trained baseline (e.g. typical login hours per
user) rather than fixed thresholds.

## SOAR playbook pattern

For each detection type, a corresponding playbook defines the automated
first response, so analysts triage instead of doing repetitive manual steps:

| Detection | Automated first response | Human decision point |
|---|---|---|
| Brute force | Auto-disable account after threshold, notify user's manager | Confirm legitimate lockout vs attack, re-enable |
| Impossible travel | Force step-up MFA challenge, alert analyst | Confirm with user directly before any account action |
| After-hours privileged access | Log + alert only (no auto-block, avoids breaking legitimate ops) | Analyst confirms activity was authorized |

## Metrics tracked

- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- False positive rate per detection rule (tuned down over time)
- % of incidents handled without manual escalation (automation coverage)
