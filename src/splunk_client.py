"""Minimal Splunk client -- runs an SPL search via the REST API (oneshot mode).
stdlib only (urllib); tolerant of Splunk's self-signed dev cert. Reads .env."""
import base64
import json
import ssl
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from config import load_env  # noqa: E402


def run_spl(query: str, count: int = 100) -> list[dict]:
    """Run an SPL search and return the result rows (list of dicts)."""
    cfg = load_env()
    host = cfg["SPLUNK_HOST"].rstrip("/")
    spl = query if query.lstrip().lower().startswith(("search", "|")) else "search " + query
    body = urllib.parse.urlencode({
        "search": spl, "output_mode": "json", "exec_mode": "oneshot", "count": str(count),
    }).encode()
    req = urllib.request.Request(host + "/services/search/jobs", data=body)
    auth = base64.b64encode(f"{cfg['SPLUNK_USER']}:{cfg['SPLUNK_PASSWORD']}".encode()).decode()
    req.add_header("Authorization", "Basic " + auth)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        return json.loads(r.read().decode()).get("results", [])


if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "index=_internal | head 5"
    rows = run_spl(q)
    print(f"✅ Splunk returned {len(rows)} rows for: {q}")
    for row in rows[:5]:
        raw = row.get("_raw") or row
        print("  -", (raw[:140] if isinstance(raw, str) else raw))
