"""Read-only HTTP security configuration review. Python 3.10+.
Usage: python audit.py https://your-authorized-site.example
       python audit.py --demo
       python audit.py --test
No crawling, exploitation, credentials or certificate bypass.
"""
import argparse, json, ssl, urllib.request, urllib.error
from urllib.parse import urlsplit

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def review(headers, https):
    h = {k.lower(): v for k, v in headers.items()}
    checks = [
        ("Content-Security-Policy", bool(h.get("content-security-policy")), "Review policy directives and application compatibility."),
        ("X-Content-Type-Options", h.get("x-content-type-options", "").lower().strip() == "nosniff", "Set nosniff."),
        ("Referrer-Policy", bool(h.get("referrer-policy")), "Select an appropriate privacy policy."),
        ("Frame protection", "frame-ancestors" in h.get("content-security-policy", "").lower() or h.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"}, "Review CSP frame-ancestors."),
    ]
    if https:
        checks.append(("HSTS", bool(h.get("strict-transport-security")), "Review max-age and deployment readiness."))
    return [{"check": n, "status": "present" if ok else "review", "guidance": g} for n, ok, g in checks]

def audit(url):
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Enter an HTTP(S) URL without credentials.")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent":"PortfolioSecurityReview/1.0"}, method="HEAD")
    try:
        response = opener.open(req, timeout=8)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return {"url": url, "status": response.code, "checks": review(response.headers, p.scheme == "https"),
                "limitations": "Single HEAD response; presence is not proof of effectiveness. Redirects are not followed."}

def test():
    assert review({"X-Content-Type-Options":"nosniff"}, False)[1]["status"] == "present"
    assert review({}, True)[-1]["status"] == "review"
    assert review({"Content-Security-Policy":"frame-ancestors 'none'"}, True)[3]["status"] == "present"

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("url", nargs="?")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--test", action="store_true")
    a = p.parse_args()
    if a.test:
        test(); print("3 checks passed")
    elif a.demo:
        print(json.dumps({"mode":"synthetic", "checks":review({"X-Content-Type-Options":"nosniff"}, True)}, indent=2))
    elif a.url:
        try: print(json.dumps(audit(a.url), indent=2))
        except (OSError, ValueError) as e: p.exit(1, str(e)+"\n")
    else: p.error("Specify an authorized URL, --demo or --test")
