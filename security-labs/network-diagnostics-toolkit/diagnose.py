"""Resolve a hostname and optionally test one authorized TCP port.
Usage: python diagnose.py example.com --port 443 | --test
No port scanning. DNS resolution uses the OS resolver.
"""
import argparse, json, socket, time

def diagnose(host, port=None):
    result = {"host":host}
    start = time.monotonic()
    try:
        result["addresses"] = sorted({a[4][0] for a in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        result["dns_ms"] = round((time.monotonic()-start)*1000, 1)
    except OSError as e:
        result["dns_error"] = str(e)
        return result
    if port is not None:
        start = time.monotonic()
        try:
            with socket.create_connection((host,port), timeout=3):
                result["tcp"] = "connected"
                result["tcp_ms"] = round((time.monotonic()-start)*1000,1)
        except OSError as e:
            result["tcp"] = "failed"; result["tcp_error"] = str(e)
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?"); p.add_argument("--port",type=int); p.add_argument("--test",action="store_true")
    a = p.parse_args()
    if a.test:
        with socket.socket() as s:
            s.bind(("127.0.0.1",0)); s.listen(1)
            r = diagnose("127.0.0.1",s.getsockname()[1])
            assert "127.0.0.1" in r["addresses"]
            assert r["tcp"] == "connected"
        print("2 checks passed")
    elif a.host and (a.port is None or 1<=a.port<=65535):
        print(json.dumps(diagnose(a.host,a.port),indent=2))
    else: p.error("Provide host and optional valid port, or --test")
