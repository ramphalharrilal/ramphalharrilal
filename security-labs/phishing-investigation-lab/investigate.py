"""Offline email triage. No links are opened and no attachments executed.
Usage: python investigate.py message.eml | --demo | --test
Authentication-Results is only trustworthy when supplied by a known receiving gateway.
"""
import argparse, json, re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

DEMO = b"From: Payroll <payroll@example.com>\nReply-To: help@invalid.example\nSubject: Payroll update\nAuthentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail\nContent-Type: text/plain\n\nReview https://login.invalid.example/update"

def analyze(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    sender = parseaddr(msg.get("From", ""))[1]
    reply = parseaddr(msg.get("Reply-To", ""))[1]
    auth = " ".join(msg.get_all("Authentication-Results", []))
    signals = []
    if reply and sender.rpartition("@")[2].lower() != reply.rpartition("@")[2].lower():
        signals.append("Reply-To domain differs")
    if re.search(r"\bdmarc\s*=\s*fail\b", auth, re.I):
        signals.append("Reported DMARC failure; verify trusted gateway")
    hosts = set()
    for part in msg.walk():
        if part.get_content_type() in {"text/plain","text/html"} and part.get_content_disposition() != "attachment":
            for url in re.findall(r'https?://[^\s<>"\']+', part.get_content()):
                try:
                    host = urlsplit(url).hostname
                    if host: hosts.add(host)
                except ValueError: pass
    return {"sender":sender, "reply_to":reply, "reported_authentication":auth, "url_hosts":sorted(hosts),
            "signals":signals, "verdict":"review required" if signals else "insufficient evidence",
            "next_steps":"Validate gateway logs, scope recipients, report to security team; do not click links."}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("file", nargs="?"); p.add_argument("--demo", action="store_true"); p.add_argument("--test", action="store_true")
    a = p.parse_args()
    if a.test:
        r = analyze(DEMO)
        assert len(r["signals"]) == 2
        assert r["url_hosts"] == ["login.invalid.example"]
        assert analyze(b"Subject: hello\n\nHi")["verdict"] == "insufficient evidence"
        print("3 checks passed")
    elif a.demo or a.file:
        print(json.dumps(analyze(DEMO if a.demo else Path(a.file).read_bytes()), indent=2))
    else: p.error("Provide a local .eml, --demo or --test")
