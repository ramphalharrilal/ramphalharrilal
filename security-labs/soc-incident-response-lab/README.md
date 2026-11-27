# Soc incident response lab

Synthetic incident IR-LAB-001: 09:00–09:02 UTC three failed logins; 09:03 success from the same fictional source 192.0.2.10. Medium priority, suspicious but not confirmed. Verify user and MFA context before any containment decision. Reproduce with `python triage.py --demo`; `python triage.py --test`. No SIEM deployment or real incident is claimed.

## Source

[triage.py](triage.py)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
