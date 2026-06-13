"""Universal behavioural detection library for SOC Sentinel.

Each detector finds malicious **behaviour or structure** — a failure burst, a
low-jitter periodic beacon, an egress-volume outlier, a service launched from a
temp directory, encoded PowerShell, a cleared audit log, a newly-public cloud
bucket — and **never references a specific IP, host, user, or hash.** No answer
keys: the same SPL that catches the intrusion in our demo would catch it on a
held-out box (the Sentinel Ensemble principle, ported to Splunk).

Each detector is parameterised by `{index}` + thresholds. `hunt()` runs the whole
pack through the Splunk MCP Server and pushes every hit through the 3-layer
validator, so each result is confirmed against real rows and given a
corroboration-based confidence (HIGH/MEDIUM/LOW)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from finding_validator import validate_finding  # noqa: E402

DEFAULT_THRESHOLDS = {
    "min_failures": 10,       # auth failures from one source => brute force
    "min_beacons": 8,         # connections to call it periodic
    "jitter_ratio": 0.25,     # stdev(interval) < ratio*mean => low-jitter beacon
    "min_exfil_bytes": 100_000_000,   # single transfer >= 100 MB
    "min_hosts": 3,           # one account into N+ hosts => lateral movement
    "min_web_hits": 1,        # attack-pattern web requests
    "min_cloud_fail": 5,      # failed cloud logins from one source
}

# Each: id, tactic, technique, title, entity (primary claim field), spl template.
DETECTIONS = [
    {
        "id": "brute_force", "tactic": "Credential Access", "technique": "T1110",
        "title": "Authentication brute force (failure burst from one source)",
        "entity": "src_ip",
        "spl": 'search index={index} (action=failure OR action=failed OR EventCode=4625 OR "failed password") src_ip=* '
               '| stats count as failures dc(user) as users_targeted by src_ip '
               '| where failures>={min_failures} | sort -failures | head 5',
    },
    {
        "id": "web_attack", "tactic": "Initial Access", "technique": "T1190",
        "title": "Web exploitation attempt (SQLi / path-traversal patterns)",
        "entity": "src_ip",
        "spl": 'search index={index} (uri="*%27*" OR uri="*\'*" OR uri="*../*" OR uri="*UNION*" OR uri="*etc/passwd*" OR uri="*OR \'1\'=\'1*") src_ip=* '
               '| stats count as hits values(status) as statuses by src_ip '
               '| where hits>={min_web_hits} | sort -hits | head 5',
    },
    {
        "id": "encoded_powershell", "tactic": "Execution", "technique": "T1059.001",
        "title": "Obfuscated / encoded PowerShell execution",
        "entity": "host",
        "spl": 'search index={index} (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*") '
               '| table _time host ParentImage Image CommandLine User | head 5',
    },
    {
        "id": "office_spawns_shell", "tactic": "Execution", "technique": "T1059",
        "title": "Office application spawned a shell / script interpreter",
        "entity": "host",
        "spl": 'search index={index} EventCode=1 (ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*powerpnt*" OR ParentImage="*outlook*") '
               '(Image="*powershell*" OR Image="*cmd.exe*" OR Image="*wscript*" OR Image="*cscript*" OR Image="*mshta*") '
               '| table _time host ParentImage Image User | head 5',
    },
    {
        "id": "service_from_temp", "tactic": "Persistence", "technique": "T1543.003",
        "title": "Service installed from a temp / user-writable path (possible rootkit/persistence)",
        "entity": "service_name",
        "spl": 'search index={index} EventCode=7045 (image_path="*Temp*" OR image_path="*Tmp*" OR image_path="*AppData*" OR image_path="*ProgramData*" OR image_path="*\\Users\\*") '
               '| table _time host service_name image_path service_type | head 5',
    },
    {
        "id": "sensitive_privilege", "tactic": "Privilege Escalation", "technique": "T1078",
        "title": "Sensitive privilege assignment (SeDebug / SeTcb / SeLoadDriver)",
        "entity": "user",
        "spl": 'search index={index} EventCode=4672 (privileges="*SeDebug*" OR privileges="*SeTcb*" OR privileges="*SeLoadDriver*" OR privileges="*SeBackup*") '
               '| table _time host user privileges | head 5',
    },
    {
        "id": "log_cleared", "tactic": "Defense Evasion", "technique": "T1070.001",
        "title": "Security / audit log cleared (anti-forensics)",
        "entity": "host",
        "spl": 'search index={index} (EventCode=1102 OR EventCode=104 OR "audit log was cleared" OR "wevtutil*cl") '
               '| table _time host user | head 5',
    },
    {
        "id": "lateral_movement", "tactic": "Lateral Movement", "technique": "T1021",
        "title": "Lateral movement (one account authenticating into many hosts)",
        "entity": "user",
        "spl": 'search index={index} (action=success OR EventCode=4624) user=* (dest_host=* OR ComputerName=*) '
               '| eval _h=coalesce(dest_host,ComputerName) '
               '| stats dc(_h) as hosts values(_h) as host_list by user '
               '| where hosts>={min_hosts} | sort -hosts | head 5',
    },
    {
        "id": "beaconing", "tactic": "Command and Control", "technique": "T1071",
        "title": "C2 beaconing (low-jitter periodic outbound)",
        "entity": "dest_ip",
        "spl": 'search index={index} dest_ip=* dest_port=* | sort 0 _time '
               '| streamstats current=f last(_time) as _prev by src_ip dest_ip '
               '| eval _delta=_time-_prev '
               '| stats count as connections avg(_delta) as avg_interval stdev(_delta) as jitter by src_ip dest_ip '
               '| where connections>={min_beacons} AND avg_interval>0 AND jitter<(avg_interval*{jitter_ratio}) '
               '| sort -connections | head 5',
    },
    {
        "id": "data_exfil", "tactic": "Exfiltration", "technique": "T1567",
        "title": "Large outbound transfer (egress-volume outlier)",
        "entity": "dest_ip",
        "spl": 'search index={index} bytes_out=* dest_ip=* '
               '| stats max(bytes_out) as max_out sum(bytes_out) as total_out by src_ip dest_ip '
               '| where max_out>={min_exfil_bytes} | sort -max_out | head 5',
    },
    {
        "id": "cloud_public_bucket", "tactic": "Exfiltration", "technique": "T1530",
        "title": "Cloud object store exposed publicly",
        "entity": "requestParameters_bucketName",
        "spl": 'search index={index} (eventName=PutBucketAcl OR eventName=PutBucketPolicy) (requestParameters_x_amz_acl="*public*" OR "AllUsers") '
               '| table _time userIdentity_userName requestParameters_bucketName requestParameters_x_amz_acl | head 5',
    },
    {
        "id": "cloud_login_failures", "tactic": "Credential Access", "technique": "T1110.004",
        "title": "Cloud console login failures from one source",
        "entity": "sourceIPAddress",
        "spl": 'search index={index} sourcetype=aws:cloudtrail eventName=ConsoleLogin errorMessage="*Failed*" '
               '| stats count as failures by sourceIPAddress | where failures>={min_cloud_fail} | sort -failures | head 5',
    },
]


def _corroborating_sources(mcp, index: str, value: str) -> list[str]:
    """Which sourcetypes independently mention this entity value (Layer-2 evidence)."""
    safe = str(value).replace('"', "")
    rows = mcp.run_query(f'search index={index} "{safe}" | stats count by sourcetype')
    return sorted({r.get("sourcetype") for r in rows if r.get("sourcetype")})


def hunt(mcp, index: str = "soc_demo", thresholds: dict | None = None) -> list[dict]:
    """Run the whole detection pack via MCP; validate every hit through the 3-layer gate."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    results = []
    for det in DETECTIONS:
        try:
            spl = det["spl"].format(index=index, **th)
            hits = mcp.run_query(spl)
        except Exception as e:  # bad SPL / tool error — record, keep going
            results.append({**_meta(det), "error": str(e)[:160], "disposition": "error"})
            continue
        if not hits:
            continue
        for hit in hits:
            val = hit.get(det["entity"])
            if not val:
                continue
            sources = _corroborating_sources(mcp, index, val) or [hit.get("sourcetype") or "?"]
            evidence = [{det["entity"]: val, "sourcetype": s} for s in sources]
            finding = {"id": det["id"], "title": f"{det['title']} — {det['entity']}={val}",
                       "claims": [{"field": det["entity"], "value": val}]}
            v = validate_finding(finding, evidence)
            results.append({**_meta(det), "value": val, "evidence": hit,
                            "disposition": v["disposition"], "confidence": v["confidence"],
                            "sources": sources})
    return results


def _meta(det: dict) -> dict:
    return {"id": det["id"], "tactic": det["tactic"], "technique": det["technique"],
            "title": det["title"], "entity": det["entity"]}


def print_hunt(results: list[dict]) -> None:
    confirmed = [r for r in results if r.get("disposition") == "confirmed"]
    print("\n" + "=" * 70)
    print(f"SOC SENTINEL — UNIVERSAL HUNT  ({len(confirmed)} confirmed across "
          f"{len(DETECTIONS)} behavioural detectors)")
    print("=" * 70)
    # order by ATT&CK-ish kill-chain as listed in DETECTIONS
    order = {d["id"]: i for i, d in enumerate(DETECTIONS)}
    for r in sorted(confirmed, key=lambda x: order.get(x["id"], 99)):
        print(f"\n[{r['confidence']:6}] {r['technique']:10} {r['tactic']}")
        print(f"         {r['title']}")
        print(f"         match: {r['entity']}={r['value']}")
        print(f"         corroborated by {len(r['sources'])} source(s): {', '.join(r['sources'])}")
    errs = [r for r in results if r.get("disposition") == "error"]
    for r in errs:
        print(f"\n[ERROR ] {r['id']}: {r['error']}")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from splunk_mcp import SplunkMCP
    idx = sys.argv[1] if len(sys.argv) > 1 else "soc_demo"
    m = SplunkMCP(); m.initialize()
    print_hunt(hunt(m, idx))
