"""Seed a self-contained, reproducible SOC dataset into Splunk (index=soc_demo).

Why this exists: a Grand-Prize demo needs *security* data, and judges should be
able to reproduce it in minutes — no 5 GB BOTS download. So we generate a small,
realistic blend of normal activity + an embedded multi-stage intrusion and ingest
it over localhost (Splunk REST `receivers/simple`, no extra ports/tokens).

IMPORTANT (no answer keys): the specific IPs/users below are *demo data only*.
The detection logic (agent SPL + validator) is behavioural and never references
these values — it finds the attack by pattern (failed-login burst, periodic
beacon, large egress), exactly as it would on a held-out box.

Embedded story (for the writer's reference, NOT given to the agent):
  1. Brute force  : external 203.0.113.66 hammers svc_backup on vpn01, then succeeds
  2. Lateral move : svc_backup then logs into many internal hosts in minutes
  3. Web attack   : same external IP probes /admin with SQLi + path traversal
  4. C2 beacon    : 10.10.0.42 calls 198.51.100.23:443 on a fixed ~60s interval
  5. Exfil        : 10.10.0.42 ships ~900 MB outbound in one burst

stdlib only; reads .env; idempotent (skips if soc_demo already has events)."""
from __future__ import annotations

import base64
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_env  # noqa: E402

INDEX = "soc_demo"
random.seed(1337)  # reproducible

cfg = load_env()
HOST = cfg["SPLUNK_HOST"].rstrip("/")
BASIC = "Basic " + base64.b64encode(
    f"{cfg['SPLUNK_USER']}:{cfg['SPLUNK_PASSWORD']}".encode()).decode()
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _send(method, path, *, data=None, params=None, ctype=None):
    url = HOST + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", BASIC)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + "Z"


def ensure_index() -> None:
    st, _ = _send("POST", "/services/data/indexes",
                  data=urllib.parse.urlencode({"name": INDEX}).encode(),
                  params={"output_mode": "json"},
                  ctype="application/x-www-form-urlencoded")
    print(f"  ensure index {INDEX}: HTTP {st} ({'created' if st in (200,201) else 'exists/again'})")


def count_events() -> int:
    body = urllib.parse.urlencode({
        "search": f"search index={INDEX} | stats count", "output_mode": "json",
        "exec_mode": "oneshot",
    }).encode()
    st, resp = _send("POST", "/services/search/jobs", data=body,
                     ctype="application/x-www-form-urlencoded")
    if st != 200:
        return 0
    rows = json.loads(resp).get("results", [])
    return int(rows[0].get("count", 0)) if rows else 0


def send_event(ts: float, sourcetype: str, source: str, host: str, kv: str) -> int:
    raw = f"{iso(ts)} {kv}"
    st, _ = _send("POST", "/services/receivers/simple", data=raw.encode(),
                  params={"index": INDEX, "sourcetype": sourcetype,
                          "source": source, "host": host},
                  ctype="text/plain")
    return st


# --------------------------------------------------------------------------
# Event generation
# --------------------------------------------------------------------------
def build_events(now: float) -> list[tuple]:
    """Return (ts, sourcetype, source, host, kv_line) tuples. ~24h window."""
    ev = []
    DAY = 86400
    users = ["alice", "bob", "carol", "dave", "eve"]
    hosts = ["web01", "web02", "db01", "app01", "vpn01", "fs01", "dc01"]
    SECURE = ("linux_secure", "/var/log/secure")
    WEB = ("access_combined", "/var/log/httpd/access_log")
    FW = ("cisco:asa", "udp:514")

    # 1) Normal auth noise across the day (legit logins)
    for _ in range(140):
        ts = now - random.uniform(0, DAY)
        u = random.choice(users)
        h = random.choice(hosts)
        sip = f"10.10.{random.randint(0,3)}.{random.randint(2,250)}"
        ev.append((ts, SECURE[0], SECURE[1], h,
                   f'app=sshd action=success user={u} src_ip={sip} dest_host={h} '
                   f'reason="Accepted password for {u}"'))

    # 2) Brute force: external IP, many failures vs svc_backup on vpn01, then success
    bf_start = now - 3 * 3600
    attacker = "203.0.113.66"
    for i in range(45):
        ts = bf_start + i * random.uniform(6, 11)
        ev.append((ts, SECURE[0], SECURE[1], "vpn01",
                   f'app=sshd action=failure user=svc_backup src_ip={attacker} '
                   f'dest_host=vpn01 reason="Failed password for svc_backup"'))
    breach = bf_start + 45 * 10
    ev.append((breach, SECURE[0], SECURE[1], "vpn01",
               f'app=sshd action=success user=svc_backup src_ip={attacker} '
               f'dest_host=vpn01 reason="Accepted password for svc_backup"'))

    # 3) Lateral movement: svc_backup hops across many internal hosts post-breach
    for j, h in enumerate(["db01", "app01", "fs01", "dc01"]):
        ts = breach + 120 + j * random.uniform(40, 90)
        ev.append((ts, SECURE[0], SECURE[1], h,
                   f'app=sshd action=success user=svc_backup src_ip=10.10.0.42 '
                   f'dest_host={h} reason="Accepted password for svc_backup"'))

    # 4) Web attack from the same external IP (SQLi + traversal), 401/403 then 200
    web_start = bf_start - 600
    web_hits = [
        ('GET /admin?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1', 403),
        ('GET /admin?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1', 403),
        ('GET /../../../../etc/passwd HTTP/1.1', 404),
        ('GET /admin/config.php HTTP/1.1', 401),
        ('POST /login HTTP/1.1', 401),
        ('POST /login HTTP/1.1', 200),
        ('GET /admin/users?export=all HTTP/1.1', 200),
    ]
    for k, (req, status) in enumerate(web_hits):
        ts = web_start + k * random.uniform(5, 20)
        ev.append((ts, WEB[0], WEB[1], "web01",
                   f'src_ip={attacker} method={req.split()[0]} '
                   f'uri="{req.split()[1]}" status={status} '
                   f'user_agent="sqlmap/1.7" bytes={random.randint(200,9000)}'))

    # web normal noise
    for _ in range(60):
        ts = now - random.uniform(0, DAY)
        sip = f"10.10.{random.randint(0,3)}.{random.randint(2,250)}"
        uri = random.choice(["/", "/index.html", "/api/health", "/products", "/cart"])
        ev.append((ts, WEB[0], WEB[1], random.choice(["web01", "web02"]),
                   f'src_ip={sip} method=GET uri="{uri}" status=200 '
                   f'user_agent="Mozilla/5.0" bytes={random.randint(300,15000)}'))

    # 5) C2 beacon: 10.10.0.42 -> 198.51.100.23:443 every ~60s (regular interval)
    c2 = "198.51.100.23"
    beacon_start = breach + 600
    for i in range(40):
        ts = beacon_start + i * (60 + random.uniform(-2, 2))  # tight ~60s cadence
        ev.append((ts, FW[0], FW[1], "fw01",
                   f'action=allowed src_ip=10.10.0.42 dest_ip={c2} dest_port=443 '
                   f'protocol=tcp bytes_out={random.randint(800,1400)} '
                   f'bytes_in={random.randint(400,900)}'))

    # 6) Exfil: one large outbound burst to the same C2 host
    ev.append((beacon_start + 40 * 60, FW[0], FW[1], "fw01",
               f'action=allowed src_ip=10.10.0.42 dest_ip={c2} dest_port=443 '
               f'protocol=tcp bytes_out=912340000 bytes_in=4200'))

    # firewall normal noise
    for _ in range(60):
        ts = now - random.uniform(0, DAY)
        sip = f"10.10.{random.randint(0,3)}.{random.randint(2,250)}"
        dip = f"{random.choice([93,142,172,8])}.{random.randint(1,254)}." \
              f"{random.randint(1,254)}.{random.randint(1,254)}"
        ev.append((ts, FW[0], FW[1], "fw01",
                   f'action=allowed src_ip={sip} dest_ip={dip} '
                   f'dest_port={random.choice([80,443,53])} protocol=tcp '
                   f'bytes_out={random.randint(500,50000)} bytes_in={random.randint(500,90000)}'))

    ev.sort(key=lambda e: e[0])
    return ev


def main() -> None:
    force = "--force" in sys.argv
    print(f"Seeding index={INDEX} on {HOST}")
    ensure_index()
    existing = count_events()
    if existing and not force:
        print(f"  index already has {existing} events — skipping (use --force to add more).")
        return

    now = time.time()
    events = build_events(now)
    print(f"  generating {len(events)} events over the last 24h…")
    ok = 0
    for ts, st_type, src, host, kv in events:
        if send_event(ts, st_type, src, host, kv) in (200, 201):
            ok += 1
    print(f"  ingested {ok}/{len(events)} events.")
    time.sleep(3)  # let the indexer catch up
    print(f"  index now holds {count_events()} events.")
    print("\n✅ Done. The agent is given only a generic SOC question; it must discover "
          "the intrusion by behaviour.")


if __name__ == "__main__":
    main()
