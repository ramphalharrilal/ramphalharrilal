# Network diagnostics toolkit

Distinguish hostname resolution from service reachability. The self-test uses an ephemeral loopback listener only. `python diagnose.py --test`. Use on your own or authorized systems. A successful TCP connection does not prove the application is healthy; DNS time includes local resolver/cache behavior.

## Source

[diagnose.py](diagnose.py)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
