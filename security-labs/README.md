# Security & IT Engineering Labs

Practical portfolio exercises with synthetic data and read-only tools. These are learning prototypes, not claims of production SOC experience or independent security certification.

| Project | Focus |
|---|---|
| [website security auditor](website-security-auditor/) | Inspect a single HTTP response for defensive headers; distinguish missing controls from confirmed vulnerabilities |
| [phishing investigation lab](phishing-investigation-lab/) | Investigate a fictional payroll email offline |
| [soc incident response lab](soc-incident-response-lab/) | Synthetic incident IR-LAB-001: 09:00–09:02 UTC three failed logins; 09:03 success from the same fictional source 192.0.2.10 |
| [sigma detection rules](sigma-detection-rules/) | Experimental Sigma rule for a narrow encoded PowerShell command indicator |
| [network diagnostics toolkit](network-diagnostics-toolkit/) | Distinguish hostname resolution from service reachability |
| [website monitor alerting](website-monitor-alerting/) | A companion exercise to the existing SiteCare project: transition deduplication |
| [wordpress security lab](wordpress-security-lab/) | Controlled WordPress hardening tabletop |
| [it helpdesk automation](it-helpdesk-automation/) | Route fictional tickets into security, network or service desk queues with transparent priority logic |

## Reproduction

Python 3.10+ standard library. Each Python project includes an offline or loopback self-test. Run the documented commands from its directory. The Sigma example requires separate backend validation. Never publish customer data, credentials, real incident artifacts or private monitoring state. Live checks require permission. No production tests or screenshots are claimed.

Related existing project: [SiteCare](https://github.com/ramphalharrilal/website-care-monitor).
