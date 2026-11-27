# Website monitor alerting

A companion exercise to the existing SiteCare project: transition deduplication. Baseline up → down emits outage → down suppresses repeats → up emits recovered. `python monitor.py --test`. HEAD checks may disagree with browser behavior; schedule externally and keep state private. No live alerts or uptime SLA are claimed.

## Source

[monitor.py](monitor.py)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
