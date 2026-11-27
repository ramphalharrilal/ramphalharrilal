"""Single-run website monitor with local state and transition-only alerts.
Usage: python monitor.py https://authorized.example --state state.json
       python monitor.py --test
Schedule externally if needed; does not send email or webhooks.
"""
import argparse, json, time, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlsplit

def check(url):
    if urlsplit(url).scheme not in {"http","https"} or not urlsplit(url).hostname:
        raise ValueError("HTTP(S) URL required")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(urllib.request.Request(url,method="HEAD"),timeout=8) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code; e.close()
    except OSError:
        status = None
    return {"status":status,"health":"up" if status is not None and 200<=status<400 else "down",
            "duration_ms":round((time.monotonic()-start)*1000,1)}

def transition(previous,current):
    if previous is None: return "baseline"
    if previous != current: return "recovered" if current == "up" else "outage"
    return "unchanged"

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("url",nargs="?"); p.add_argument("--state",default="state.json"); p.add_argument("--test",action="store_true")
    a = p.parse_args()
    if a.test:
        assert transition(None,"up")=="baseline"
        assert transition("up","down")=="outage"
        assert transition("down","down")=="unchanged"
        assert transition("down","up")=="recovered"
        print("4 checks passed")
    elif a.url:
        path=Path(a.state)
        old=json.loads(path.read_text()) if path.exists() else {}
        result=check(a.url)
        result["event"]=transition(old.get(a.url),result["health"])
        old[a.url]=result["health"]
        tmp=path.with_suffix(path.suffix+".tmp"); tmp.write_text(json.dumps(old)); tmp.replace(path)
        print(json.dumps(result,indent=2))
    else: p.error("Provide URL or --test")
