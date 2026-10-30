# Detection Engineering Lab: Detection-as-Code

![ci](https://github.com/Saivignesh-1177/detection-engineering-lab/actions/workflows/ci.yml/badge.svg)

A Sigma-inspired detection pipeline written from scratch: **rules as code, unit-tested like software, mapped
to MITRE ATT&CK, and gated in CI**. It covers Windows (Sysmon / Security log), Linux (auditd execve), and AWS
CloudTrail.

```
rules/*.json ──► detlab engine ──► alerts ──► SOC triage
      │                ▲
      └─ tests/fixtures (true-positive + true-negative events per rule) ── CI gate
```

## Rule pack

| Rule | Detects | ATT&CK | Level |
|---|---|---|---|
| DET-001 | Encoded PowerShell | T1059.001, T1027 | high |
| DET-002 | LSASS memory access (credential dumping) | T1003.001 | critical |
| DET-003 | Office app spawning a shell (malicious macro) | T1566.001, T1204.002 | high |
| DET-004 | Brute force / password spray (**threshold rule**: 5 failures / 60 s / source IP) | T1110.001, T1110.003 | medium |
| DET-005 | Scheduled-task persistence | T1053.005 | medium |
| DET-006 | Shadow-copy deletion (ransomware precursor) | T1490 | critical |
| DET-007 | Security log cleared | T1070.001 | high |
| DET-008 | `curl \| sh` remote script execution (Linux) | T1105, T1059.004 | high |
| DET-009 | CloudTrail stopped/deleted (AWS) | T1562.008 | critical |

The full tactic-by-technique matrix is in [`docs/coverage.md`](docs/coverage.md). It is generated, never hand-edited.

## Engineering practices shown

- **Every rule has to ship with fixtures.** CI fails if a rule is missing a true-positive or true-negative event.
- **Tuned filters.** Known-good parents such as SCCM, Defender, and msiexec are filtered, and each filter has a
  true negative proving it works.
- **Stateful detections.** Sliding-window thresholds grouped by a field, alerting once per group.
- **Required metadata.** Severity, ATT&CK mapping, and documented false positives on every rule.
- **Fail-safe parsing.** Unknown match modifiers raise an error at load time instead of silently never matching.

## Run it

```bash
python tools/build_content.py                    # regenerate rules, fixtures, and the simulated day
python -m unittest -v                            # detection-as-code test suite
python -m detlab hunt data/intrusion-day.jsonl   # replay a simulated intrusion (exit 1 on critical)
python -m detlab coverage                        # rebuild docs/coverage.md
```

`data/intrusion-day.jsonl` is **synthetic**. It contains handcrafted events that follow real Sysmon /
Security / CloudTrail field names, mixed with benign noise. Before production use, validate the rules against
real telemetry, for example from an Atomic Red Team run in an isolated lab.

## Rule format

```json
{
  "id": "DET-004", "title": "Password spraying / brute force from one source", "level": "medium",
  "attack": ["T1110.001", "T1110.003"],
  "logsource": {"product": "windows", "EventID": 4625},
  "selection": {"LogonType": [3, 10]},
  "threshold": {"count": 5, "window_s": 60, "group_by": "IpAddress"},
  "falsepositives": ["Service account with a stale password"]
}
```

Match modifiers: `equals` (default), `contains`, `startswith`, `endswith`, `re`. All of them are case-insensitive.

## Next steps

- [ ] Export rules to Sigma YAML, then to KQL / SPL via pySigma
- [ ] Validate against Atomic Red Team logs from a lab VM
- [ ] Add parent/child process correlation rules
