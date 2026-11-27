"""SZARA Website Configuration Review | Python 3.10+ | authorized use only."""
import argparse
import html
import http.client
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LIMITS = ("One URL and one HEAD response; redirects are not followed. "
          "DNS uses the local resolver. Header presence is not proof of effectiveness. "
          "No crawling, exploitation, authentication, malware checks or compliance certification.")

def finding(control, status, priority, evidence, action):
    return dict(control=control, status=status, priority=priority,
                evidence=evidence, action=action)

def review(headers, https):
    h = {k.lower(): v for k, v in headers.items()}
    csp = h.get("content-security-policy", "")
    frame = any(x.strip().lower().startswith("frame-ancestors ") for x in csp.split(";"))
    frame = frame or h.get("x-frame-options", "").strip().upper() in {"DENY", "SAMEORIGIN"}
    controls = [
        ("Content Security Policy", bool(csp.strip()), "medium", "Review directives against application needs."),
        ("MIME sniffing protection", h.get("x-content-type-options", "").strip().lower() == "nosniff", "low", "Set X-Content-Type-Options: nosniff."),
        ("Referrer policy", bool(h.get("referrer-policy", "").strip()), "low", "Choose and test a privacy-conscious policy."),
        ("Frame protection", frame, "medium", "Review CSP frame-ancestors or X-Frame-Options."),
    ]
    if https:
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", h.get("strict-transport-security", ""), re.I)
        controls.append(("HSTS", bool(match and int(match.group(1)) > 0), "medium",
                         "Review HTTPS readiness and configure a positive HSTS max-age."))
    return [finding(n, "observed" if ok else "review", "info" if ok else pr,
                    "Expected indicator observed" if ok else "Expected indicator not observed", a)
            for n, ok, pr, a in controls]

def tls_finding(cert, now):
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days = (expires - now).days
    return finding("TLS certificate", "review" if days < 30 else "observed",
                   "high" if days < 7 else "medium" if days < 30 else "info",
                   f"Verified connection; expires {expires.isoformat()} ({days} full days remaining)",
                   "Confirm automatic renewal and monitor expiration.")

def make_report(url, mode, findings, now=None):
    now = now or datetime.now(timezone.utc)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings = sorted(findings, key=lambda f: order[f["priority"]])
    counts = {p: sum(f["priority"] == p for f in findings) for p in order}
    return {"title": "SZARA Website Configuration Review", "target": url, "mode": mode,
            "checked_at_utc": now.isoformat(), "summary": counts,
            "findings": findings, "limitations": LIMITS}

def target(url):
    p = urlsplit(url)
    if (p.scheme not in {"http", "https"} or not p.hostname or p.username is not None
            or p.password is not None or p.query or p.fragment):
        raise ValueError("Use an HTTP(S) URL without credentials, query or fragment.")
    if any(ord(c) < 32 for c in url):
        raise ValueError("Invalid URL.")
    return p, p.port or (443 if p.scheme == "https" else 80)

def audit(url):
    p, port = target(url)
    https = p.scheme == "https"
    findings = []
    try:
        addresses = {a[4][0] for a in socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)}
        findings.append(finding("DNS resolution", "observed", "info",
                                f"{len(addresses)} unique address(es) returned", "Confirm records against intended hosting."))
    except OSError:
        findings.append(finding("DNS resolution", "review", "high", "Resolution failed from this network",
                                "Check DNS configuration and retest from another resolver."))
        return make_report(url, "live", findings)
    if not https:
        findings.append(finding("HTTPS transport", "review", "high", "Requested URL uses HTTP",
                                "Verify HTTPS and redirect HTTP traffic where appropriate."))
    conn = (http.client.HTTPSConnection(p.hostname, port, timeout=8, context=ssl.create_default_context())
            if https else http.client.HTTPConnection(p.hostname, port, timeout=8))
    try:
        conn.connect()
        if https:
            findings.append(tls_finding(conn.sock.getpeercert(), datetime.now(timezone.utc)))
        conn.request("HEAD", p.path or "/", headers={"User-Agent": "SZARA-ConfigurationReview/1.0"})
        with conn.getresponse() as response:
            status = response.status
            ok = 200 <= status < 300
            redirect = 300 <= status < 400
            findings.append(finding("HTTP response", "observed" if ok else "review",
                                    "info" if ok else "low" if redirect else "medium", f"HTTP {status}",
                                    "Confirm the intended page; redirects are not followed."))
            if ok:
                findings.extend(review(dict(response.getheaders()), https))
            else:
                findings.append(finding("Security headers", "not assessed", "info",
                                        "No successful page response", "Review the authorized destination separately."))
    except ssl.SSLCertVerificationError:
        findings.append(finding("TLS certificate", "review", "high", "Certificate verification failed",
                                "Check expiration, trust chain and hostname. Do not bypass verification."))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        findings.append(finding("Connection", "review", "medium", type(exc).__name__,
                                "Verify reachability from another network; do not assume downtime."))
    finally:
        conn.close()
    return make_report(url, "live", findings)

def demo():
    now = datetime(2026, 11, 27, tzinfo=timezone.utc)
    f = [finding("DNS resolution", "observed", "info", "2 synthetic addresses", "Confirm intended hosting."),
         finding("TLS certificate", "review", "medium", "Synthetic certificate expires in 14 days", "Verify renewal."),
         finding("HTTP response", "observed", "info", "Synthetic HTTP 200", "No action required.")]
    return make_report("https://demo.example", "synthetic demonstration",
                       f + review({"X-Content-Type-Options": "nosniff"}, True), now)

def render(report):
    e = lambda v: html.escape(str(v), quote=True)
    rows = "".join("<tr>" + "".join(f"<td>{e(f[k])}</td>" for k in
                   ("priority", "control", "status", "evidence", "action")) + "</tr>" for f in report["findings"])
    counts = "".join(f"<div><strong>{e(v)}</strong><span>{e(k.title())}</span></div>"
                     for k, v in report["summary"].items())
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(report['title'])}</title>
<style>
*{{box-sizing:border-box}}body{{font:16px/1.55 system-ui,sans-serif;color:#172a38;background:#edf2f4;margin:0}}
main{{max-width:1100px;margin:30px auto;background:white;padding:clamp(16px,4vw,40px)}}
header{{border-bottom:3px solid #147d80;padding-bottom:16px}}small{{letter-spacing:.12em;color:#147d80;font-weight:700}}
h1{{font-size:clamp(24px,4vw,36px);line-height:1.2;margin:8px 0}}p{{overflow-wrap:anywhere}}
.summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:24px 0}}
.summary div{{background:#e8f1f1;padding:12px}}strong,span{{display:block}}strong{{font-size:27px}}
.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #d5e0e3}}th{{background:#173744;color:white}}
footer{{margin-top:24px;color:#435765;font-size:13px}}@media print{{body{{background:white}}main{{margin:0;padding:0}}tr{{break-inside:avoid}}}}
</style><main><header><small>SZARA / TECHNICAL REVIEW</small><h1>{e(report['title'])}</h1>
<p>{e(report['target'])}<br>Mode: {e(report['mode'])}<br>UTC: {e(report['checked_at_utc'])}</p></header>
<section class="summary" aria-label="Findings by priority">{counts}</section>
<h2>Recommended actions</h2><p>Priorities reflect configuration observations, not confirmed exploitability.</p>
<div class="scroll"><table><thead><tr><th>Priority</th><th>Control</th><th>Status</th><th>Evidence</th><th>Recommended action</th></tr></thead><tbody>{rows}</tbody></table></div>
<footer><h2>Scope and limitations</h2><p>{e(report['limitations'])}</p><p>Point-in-time review only. Validate changes with the site owner before implementation.</p></footer></main></html>"""

def test():
    from unittest.mock import patch
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    assert review({"X-Content-Type-Options": "nosniff"}, False)[1]["status"] == "observed"
    assert review({"Strict-Transport-Security": "max-age=0"}, True)[-1]["status"] == "review"
    assert review({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}, True)[-1]["status"] == "observed"
    assert review({"Content-Security-Policy": "frame-ancestors 'none'"}, True)[3]["status"] == "observed"
    assert tls_finding({"notAfter": "Dec  1 00:00:00 2026 GMT"}, datetime(2026, 11, 27, tzinfo=timezone.utc))["priority"] == "high"
    assert sum(demo()["summary"].values()) == len(demo()["findings"])
    assert "&lt;script&gt;" in render(make_report("<script>", "test", []))
    for url in ("ftp://example.com", "https://user@example.com", "https://example.com/?token=x"):
        try:
            target(url)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid URL accepted")
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        assert audit("https://demo.example")["findings"][0]["control"] == "DNS resolution"
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
        def log_message(self, *args):
            pass
    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = audit(f"http://127.0.0.1:{server.server_port}/")
            assert any(f["control"] == "HTTP response" and f["status"] == "observed" for f in result["findings"])
            assert any(f["control"] == "MIME sniffing protection" and f["status"] == "observed" for f in result["findings"])
        finally:
            server.shutdown()
            thread.join()
    print("Header, TLS fixture, report escaping, URL validation, DNS failure and local HTTP checks passed.")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("url", nargs="?")
    p.add_argument("--authorized", action="store_true", help="Confirm permission for live checks")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--test", action="store_true")
    p.add_argument("--output", type=Path, help="Output directory for report.json and report.html")
    a = p.parse_args()
    if a.test:
        test()
    else:
        if a.demo and not a.url:
            result = demo()
        elif a.url and a.authorized and not a.demo:
            try:
                result = audit(a.url)
            except ValueError as exc:
                p.error(str(exc))
        else:
            p.error("Choose --demo, --test, or an authorized URL with --authorized.")
        if a.output:
            a.output.mkdir(parents=True, exist_ok=True)
            (a.output / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            (a.output / "report.html").write_text(render(result), encoding="utf-8")
        print(json.dumps(result, indent=2))
