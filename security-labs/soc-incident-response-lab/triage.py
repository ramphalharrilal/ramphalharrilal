"""Offline SOC alert triage using synthetic JSON events.
Usage: python triage.py --demo | --test | events.json
Detects a successful login after at least three failures in a ten-minute window.
"""
import argparse, json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

DEMO = [{"time":f"2026-11-01T09:0{i}:00+00:00","user":"demo.user","ip":"192.0.2.10","outcome":v}
        for i,v in enumerate(["failure","failure","failure","success"])]

def triage(events):
    failures = defaultdict(list)
    alerts = []
    for e in sorted(events, key=lambda e:datetime.fromisoformat(e["time"])):
        t = datetime.fromisoformat(e["time"])
        key = (e["user"],e["ip"])
        recent = [x for x in failures[key] if t-timedelta(minutes=10) <= x <= t]
        if e["outcome"] == "failure":
            recent.append(t)
        elif e["outcome"] == "success":
            if len(recent) >= 3:
                alerts.append({"severity":"medium", "time":e["time"], "user":e["user"], "ip":e["ip"],
                               "failures":len(recent), "verdict":"suspicious; unconfirmed",
                               "next_steps":"Check MFA, device, source context and user confirmation; escalate per policy."})
            recent = []
        failures[key] = recent
    return alerts

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("file", nargs="?"); p.add_argument("--demo",action="store_true"); p.add_argument("--test",action="store_true")
    a = p.parse_args()
    if a.test:
        assert len(triage(DEMO)) == 1
        assert not triage(DEMO[:3])
        assert not triage([DEMO[-1]])
        assert not triage(DEMO + [{**DEMO[-1],"time":"2026-11-01T09:04:00+00:00"}])[1:]
        print("4 checks passed")
    elif a.demo or a.file:
        print(json.dumps(triage(DEMO if a.demo else json.loads(Path(a.file).read_text())), indent=2))
    else: p.error("Provide JSON, --demo or --test")
