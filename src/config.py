"""Load SOC-Sentinel-Splunk config from .env (env vars override)."""
import os

_KEYS = ("SPLUNK_HOST", "SPLUNK_USER", "SPLUNK_PASSWORD",
         "SPLUNK_MCP_URL", "SPLUNK_MCP_TRANSPORT", "SPLUNK_MCP_TOKEN")

def load_env(path=None):
    cfg = {}
    p = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.isfile(p):
        for ln in open(p, encoding="utf-8"):
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            cfg[k.strip()] = v.split(" #")[0].strip()
    for k in _KEYS:
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg
