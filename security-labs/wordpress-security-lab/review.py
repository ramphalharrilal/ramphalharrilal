"""Offline WordPress configuration review of a sanitized JSON inventory.
Usage: python review.py --demo | --test | inventory.json
No requests to WordPress or exploitation.
"""
import argparse, json
from pathlib import Path

DEMO={"https":True,"mfa_admin":False,"auto_updates":False,"backup_restore_tested":False,
      "file_editor_disabled":True,"unused_plugins":2,"administrator_count":3}

def review(data):
    checks=[
        ("HTTPS configured","https","Verify certificate and HTTPS redirects."),
        ("Admin MFA","mfa_admin","Enable MFA with recovery procedures."),
        ("Update process","auto_updates","Define timely tested updates."),
        ("Restore tested","backup_restore_tested","Verify isolated backup restoration."),
        ("Dashboard editor disabled","file_editor_disabled","Consider disabling dashboard code editing.")
    ]
    findings=[]
    for name,key,advice in checks:
        val=data.get(key)
        findings.append({"control":name,"status":"reported enabled" if val is True else "review" if val is False else "unknown","action":advice})
    n=data.get("unused_plugins")
    findings.append({"control":"Unused plugins","status":"unknown" if n is None else "review" if n>0 else "reported none","action":"Remove unused plugins after backup and dependency review."})
    return findings

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("file",nargs="?"); p.add_argument("--demo",action="store_true"); p.add_argument("--test",action="store_true"); a=p.parse_args()
    if a.test:
        assert review(DEMO)[1]["status"]=="review"
        assert review({})[0]["status"]=="unknown"
        assert review({"unused_plugins":0})[-1]["status"]=="reported none"
        print("3 checks passed")
    elif a.demo or a.file:
        print(json.dumps(review(DEMO if a.demo else json.loads(Path(a.file).read_text())),indent=2))
    else: p.error("Provide inventory, --demo or --test")
