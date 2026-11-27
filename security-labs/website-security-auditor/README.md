# Website security auditor

Inspect a single HTTP response for defensive headers; distinguish missing controls from confirmed vulnerabilities. Demo uses synthetic headers. A valid TLS connection is required for HTTPS; this is not a certificate-expiry scanner or penetration test. Try `python audit.py --demo` and `python audit.py --test`. Document status, header observations, owner-approved changes and retest results.

## Source

[audit.py](audit.py)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
