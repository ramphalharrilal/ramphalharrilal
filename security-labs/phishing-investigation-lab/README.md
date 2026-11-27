# Phishing investigation lab

Investigate a fictional payroll email offline. Expected observations: reported DMARC fail, reply-to mismatch and a reserved fictional link domain. Verdict: review required, not confirmed compromise. Scope recipients via authorized gateway records; preserve evidence; escalate. `python investigate.py --demo` / `--test`. Never publish real messages, addresses or tokens.

## Source

[investigate.py](investigate.py)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
