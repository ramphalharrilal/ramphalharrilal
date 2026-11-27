# SZARA Website Configuration Review

A read-only Python 3.10+ utility that helps website owners understand basic configuration observations and prioritize remediation. This is a portfolio prototype, not a penetration test or certification.

## What it checks

| Area | Observation | Why it matters |
|---|---|---|
| DNS | Local hostname resolution | Whether the hostname resolves from the testing network |
| HTTPS | Certificate verification and expiry for HTTPS URLs | Browser trust and renewal planning |
| HTTP | One HEAD response, no redirects followed | Whether the requested endpoint responds as expected |
| Security headers | CSP, MIME sniffing, referrer policy, frame protection, HSTS | Browser defense indicators and configuration review |

The report prioritizes findings as high, medium, low or informational. Missing indicators are not proof of a vulnerability; priorities are heuristic, not CVSS scores.

## Run the fictional demonstration

No external requests or paid dependencies:

```bash
python audit.py --demo --output reports/demo
python audit.py --test
```

Open `reports/demo/report.html` in a browser. The JSON contains the same observations. The HTML is self-contained and can be printed to PDF through the browser. The demo is explicitly synthetic.

## Run an authorized assessment

Only use a website you own or have explicit permission to review. Substitute its approved URL:

```bash
python audit.py https://example.com --authorized --output reports/client
```

Keep reports private unless the owner authorizes disclosure. Do not include credentials, URL query tokens, client information or private incident evidence in GitHub. The --authorized switch is an operator declaration, not a technical authorization control.

## Review workflow

1. Establish scope and the approved target with the site owner.
2. Run the tool, check the mode, timestamp and findings.
3. Manually verify any observation before recommending a change.
4. Agree remediation, test on staging, and retest after authorized changes.
5. Share the report privately with the owner.

## Testing and limitations

Self-tests cover header indicators, TLS expiry using a fixture, report escaping, URL validation, simulated DNS failure, and an actual loopback HTTP response. GitHub Actions is configured to run these tests. A green test run must be verified before claiming success. Live TLS integration and broader browser compatibility remain unverified.

No redirect following, crawling, exploit testing, form submissions, software vulnerability scanning, authentication, malware detection or compliance certification. DNS resolution is network-specific and uses the OS resolver. Header presence does not establish policy effectiveness. HTTP HEAD may differ from browser GET responses. This is a point-in-time configuration review, not a guarantee of security.

[Source code](audit.py) · [Existing SiteCare monitor](https://github.com/ramphalharrilal/website-care-monitor)
