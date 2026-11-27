"""Offline help-desk ticket routing using simple transparent rules.
Usage: python route.py --demo | --test | tickets.json
Human review required; no external ticket system changes.
"""
import argparse, json
from pathlib import Path

DEMO=[{"id":"LAB-1","summary":"Suspicious phishing email","affected":"one"},
      {"id":"LAB-2","summary":"Network outage","affected":"many"},
      {"id":"LAB-3","summary":"Printer offline","affected":"one"}]

def route(ticket):
    s=ticket["summary"].casefold()
    security=any(x in s for x in ("phishing","malware","account compromise","ransomware"))
    if security: queue="security"; priority="urgent"
    elif any(x in s for x in ("network","vpn","dns","wifi")): queue="network"; priority="high" if ticket.get("affected")=="many" else "normal"
    else: queue="service desk"; priority="high" if ticket.get("affected")=="many" else "normal"
    return {"id":ticket["id"],"queue":queue,"priority":priority,"review_required":True}

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("file",nargs="?"); p.add_argument("--demo",action="store_true"); p.add_argument("--test",action="store_true"); a=p.parse_args()
    if a.test:
        assert route(DEMO[0])["queue"]=="security"
        assert route(DEMO[1])["priority"]=="high"
        assert route(DEMO[2])["queue"]=="service desk"
        assert route({"id":"x","summary":"Other issue","affected":"many"})["priority"]=="high"
        print("4 checks passed")
    elif a.demo or a.file:
        print(json.dumps([route(t) for t in (DEMO if a.demo else json.loads(Path(a.file).read_text()))],indent=2))
    else: p.error("Provide tickets, --demo or --test")
