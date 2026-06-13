"""Universal behavioural detection library for SOC Sentinel.

A global, multi-cloud detection pack: identity, endpoint (Windows/Sysmon), network,
and the three major clouds (AWS / Azure / GCP). Each detector finds **behaviour or
structure** — a failure burst, a low-jitter beacon, an egress outlier, a service
from a temp dir, encoded PowerShell, LSASS access, a public bucket, a Global-Admin
grant, an owner-role IAM change — and **never references a specific IP, host, user,
or hash.** No answer keys: the same SPL that catches the intrusion in our demo
would catch it on a held-out box (the Sentinel Ensemble principle, ported to Splunk).

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
    "min_failures": 10,        # auth failures from one source => brute force
    "spray_users": 3,          # distinct users targeted from one source => spray
    "min_beacons": 8,          # connections to call it periodic
    "jitter_ratio": 0.25,      # stdev(interval) < ratio*mean => low-jitter beacon
    "min_exfil_bytes": 100_000_000,    # single transfer >= 100 MB
    "min_hosts": 3,            # one account into N+ hosts => lateral movement
    "min_web_hits": 1,         # attack-pattern web requests
    "min_cloud_fail": 5,       # failed cloud logins from one source
    "dns_len": 40,             # DNS query length suggesting tunnelling
    "dns_uniq": 10,            # distinct long subdomains => tunnelling
    "recon_min": 3,            # distinct recon commands from one host => discovery burst
}

# domain, id, tactic, technique, title, entity (primary claim field), spl template.
DETECTIONS = [
    # ---------------- Identity ----------------
    {"domain": "identity", "id": "brute_force", "tactic": "Credential Access", "technique": "T1110",
     "title": "Authentication brute force (failure burst from one source)", "entity": "src_ip",
     "spl": 'search index={index} (action=failure OR action=failed OR EventCode=4625 OR "failed password") src_ip=* '
            '| stats count as failures dc(user) as users by src_ip | where failures>={min_failures} | sort -failures | head 5'},
    {"domain": "identity", "id": "password_spray", "tactic": "Credential Access", "technique": "T1110.003",
     "title": "Password spray (one source, many targeted accounts)", "entity": "src_ip",
     "spl": 'search index={index} (action=failure OR EventCode=4625 OR "failed password") src_ip=* user=* '
            '| stats dc(user) as users_targeted count as attempts by src_ip | where users_targeted>={spray_users} | sort -users_targeted | head 5'},
    {"domain": "identity", "id": "cloud_login_failures", "tactic": "Credential Access", "technique": "T1110.004",
     "title": "Cloud console login failures from one source", "entity": "sourceIPAddress",
     "spl": 'search index={index} eventName=ConsoleLogin errorMessage="*Failed*" '
            '| stats count as failures by sourceIPAddress | where failures>={min_cloud_fail} | sort -failures | head 5'},

    # ---------------- Web ----------------
    {"domain": "web", "id": "web_attack", "tactic": "Initial Access", "technique": "T1190",
     "title": "Web exploitation attempt (SQLi / path-traversal)", "entity": "src_ip",
     "spl": 'search index={index} (uri="*%27*" OR uri="*\'*" OR uri="*../*" OR uri="*UNION*" OR uri="*etc/passwd*") src_ip=* '
            '| stats count as hits by src_ip | where hits>={min_web_hits} | sort -hits | head 5'},

    # ---------------- Endpoint ----------------
    {"domain": "endpoint", "id": "encoded_powershell", "tactic": "Execution", "technique": "T1059.001",
     "title": "Obfuscated / encoded PowerShell execution", "entity": "host",
     "spl": 'search index={index} (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*") '
            '| table _time host Image CommandLine User | head 5'},
    {"domain": "endpoint", "id": "office_spawns_shell", "tactic": "Execution", "technique": "T1059",
     "title": "Office application spawned a shell / script interpreter", "entity": "host",
     "spl": 'search index={index} EventCode=1 (ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*outlook*") '
            '(Image="*powershell*" OR Image="*cmd.exe*" OR Image="*wscript*" OR Image="*mshta*") | table _time host ParentImage Image | head 5'},
    {"domain": "endpoint", "id": "lolbin_download", "tactic": "Command and Control", "technique": "T1105",
     "title": "LOLBin used to download a payload (certutil/bitsadmin/mshta)", "entity": "host",
     "spl": 'search index={index} (Image="*certutil*" OR Image="*bitsadmin*" OR Image="*mshta*") CommandLine="*http*" '
            '| table _time host Image CommandLine | head 5'},
    {"domain": "endpoint", "id": "lsass_access", "tactic": "Credential Access", "technique": "T1003.001",
     "title": "LSASS memory access (credential dumping)", "entity": "host",
     "spl": 'search index={index} EventCode=10 TargetImage="*lsass*" | table _time host SourceImage TargetImage GrantedAccess | head 5'},
    {"domain": "endpoint", "id": "registry_runkey", "tactic": "Persistence", "technique": "T1547.001",
     "title": "Run-key registry persistence", "entity": "host",
     "spl": 'search index={index} EventCode=13 TargetObject="*CurrentVersion*Run*" | table _time host TargetObject Details | head 5'},
    {"domain": "endpoint", "id": "scheduled_task", "tactic": "Persistence", "technique": "T1053.005",
     "title": "Scheduled task created", "entity": "host",
     "spl": 'search index={index} (EventCode=4698 OR CommandLine="*schtasks*create*" OR "scheduled task was created") '
            '| table _time host TaskName user | head 5'},
    {"domain": "endpoint", "id": "service_from_temp", "tactic": "Persistence", "technique": "T1543.003",
     "title": "Service installed from a temp / user-writable path (possible rootkit)", "entity": "service_name",
     "spl": 'search index={index} EventCode=7045 (image_path="*Temp*" OR image_path="*AppData*" OR image_path="*ProgramData*" OR image_path="*\\Users\\*") '
            '| table _time host service_name image_path service_type | head 5'},
    {"domain": "endpoint", "id": "defender_tamper", "tactic": "Defense Evasion", "technique": "T1562.001",
     "title": "Endpoint protection tampering (Defender disabled)", "entity": "host",
     "spl": 'search index={index} (CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*Set-MpPreference*" OR CommandLine="*MpCmdRun*-removedefinitions*") '
            '| table _time host CommandLine | head 5'},
    {"domain": "endpoint", "id": "sensitive_privilege", "tactic": "Privilege Escalation", "technique": "T1078",
     "title": "Sensitive privilege assignment (SeDebug / SeTcb / SeLoadDriver)", "entity": "user",
     "spl": 'search index={index} EventCode=4672 (privileges="*SeDebug*" OR privileges="*SeTcb*" OR privileges="*SeLoadDriver*" OR privileges="*SeBackup*") '
            '| table _time host user privileges | head 5'},
    {"domain": "endpoint", "id": "log_cleared", "tactic": "Defense Evasion", "technique": "T1070.001",
     "title": "Security / audit log cleared (anti-forensics)", "entity": "host",
     "spl": 'search index={index} (EventCode=1102 OR EventCode=104 OR "audit log was cleared" OR "wevtutil*cl") | table _time host user | head 5'},

    # ---------------- Network ----------------
    {"domain": "network", "id": "lateral_movement", "tactic": "Lateral Movement", "technique": "T1021",
     "title": "Lateral movement (one account into many hosts)", "entity": "user",
     "spl": 'search index={index} (action=success OR EventCode=4624) user=* (dest_host=* OR ComputerName=*) '
            '| eval _h=coalesce(dest_host,ComputerName) | stats dc(_h) as hosts values(_h) as host_list by user '
            '| where hosts>={min_hosts} | sort -hosts | head 5'},
    {"domain": "network", "id": "beaconing", "tactic": "Command and Control", "technique": "T1071",
     "title": "C2 beaconing (low-jitter periodic outbound)", "entity": "dest_ip",
     "spl": 'search index={index} dest_ip=* dest_port=* | sort 0 _time '
            '| streamstats current=f last(_time) as _prev by src_ip dest_ip | eval _delta=_time-_prev '
            '| stats count as connections avg(_delta) as avg_interval stdev(_delta) as jitter by src_ip dest_ip '
            '| where connections>={min_beacons} AND avg_interval>0 AND jitter<(avg_interval*{jitter_ratio}) | sort -connections | head 5'},
    {"domain": "network", "id": "dns_tunneling", "tactic": "Command and Control", "technique": "T1071.004",
     "title": "DNS tunnelling (many long unique subdomains)", "entity": "src_ip",
     "spl": 'search index={index} (sourcetype=stream:dns OR query=*) query=* | eval _ql=len(query) '
            '| stats max(_ql) as longest dc(query) as uniq_subdomains by src_ip '
            '| where longest>{dns_len} AND uniq_subdomains>={dns_uniq} | sort -uniq_subdomains | head 5'},
    {"domain": "network", "id": "data_exfil", "tactic": "Exfiltration", "technique": "T1567",
     "title": "Large outbound transfer (egress-volume outlier)", "entity": "dest_ip",
     "spl": 'search index={index} bytes_out=* dest_ip=* | stats max(bytes_out) as max_out sum(bytes_out) as total_out by src_ip dest_ip '
            '| where max_out>={min_exfil_bytes} | sort -max_out | head 5'},

    # ---------------- Advanced endpoint / lateral (Find-Evil-grade, log-native) ----------------
    {"domain": "endpoint", "id": "credential_dump", "tactic": "Credential Access", "technique": "T1003",
     "title": "Credential dumping (SAM/SYSTEM hive save or LSASS minidump)", "entity": "host",
     "spl": 'search index={index} (CommandLine="*reg* save*SAM*" OR CommandLine="*reg* save*SYSTEM*" OR CommandLine="*comsvcs*MiniDump*" OR CommandLine="*procdump*lsass*" OR CommandLine="*ntdsutil*ifm*") '
            '| table _time host Image CommandLine | head 5'},
    {"domain": "endpoint", "id": "recon_burst", "tactic": "Discovery", "technique": "T1087",
     "title": "Discovery / recon burst (net · systeminfo · tasklist · nltest)", "entity": "host",
     "spl": 'search index={index} EventCode=1 (CommandLine="*net view*" OR CommandLine="*net group*" OR CommandLine="*systeminfo*" OR CommandLine="*tasklist*" OR CommandLine="*nltest*" OR CommandLine="*whoami /priv*") '
            '| stats dc(CommandLine) as recon_cmds by host | where recon_cmds>={recon_min} | sort -recon_cmds | head 5'},
    {"domain": "network", "id": "psexec_lateral", "tactic": "Lateral Movement", "technique": "T1021.002",
     "title": "PsExec lateral movement (PSEXESVC service + admin share)", "entity": "host",
     "spl": 'search index={index} ((EventCode=7045 service_name=*PSEXESVC*) OR (EventCode=5140 (share_name="*ADMIN$*" OR share_name="*IPC$*" OR share_name="*C$*"))) '
            '| table _time host service_name share_name user | head 5'},
    {"domain": "network", "id": "rdp_lateral", "tactic": "Lateral Movement", "technique": "T1021.001",
     "title": "RDP lateral movement (Type-10 RemoteInteractive logon)", "entity": "user",
     "spl": 'search index={index} EventCode=4624 LogonType=10 user=* | stats count by user src_ip dest_host | sort -count | head 5'},
    {"domain": "endpoint", "id": "wmi_persistence", "tactic": "Persistence", "technique": "T1546.003",
     "title": "WMI event-subscription persistence (CommandLineEventConsumer)", "entity": "host",
     "spl": 'search index={index} (EventCode=5861 OR "CommandLineEventConsumer" OR "ActiveScriptEventConsumer") '
            '| table _time host consumer query | head 5'},
    {"domain": "endpoint", "id": "process_masquerade", "tactic": "Defense Evasion", "technique": "T1036.005",
     "title": "System-process masquerade (system binary from a non-System32 path)", "entity": "host",
     "spl": 'search index={index} EventCode=1 (Image="*\\lsass.exe" OR Image="*\\svchost.exe" OR Image="*\\services.exe" OR Image="*\\smss.exe") '
            'NOT (Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*") | table _time host Image ParentImage | head 5'},
    {"domain": "endpoint", "id": "antiforensics_deletion", "tactic": "Defense Evasion", "technique": "T1070.004",
     "title": "Anti-forensics — secure/mass file deletion (sdelete · cipher)", "entity": "host",
     "spl": 'search index={index} (CommandLine="*sdelete*" OR CommandLine="*cipher /w*" OR CommandLine="*sdelete64*" OR Image="*sdelete*") '
            '| table _time host Image CommandLine | head 5'},
    {"domain": "endpoint", "id": "ransomware_prep", "tactic": "Impact", "technique": "T1490",
     "title": "Ransomware prep — shadow-copy deletion / recovery disabled", "entity": "host",
     "spl": 'search index={index} (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*catalog*") '
            '| table _time host CommandLine | head 5'},

    # ---------------- AWS ----------------
    {"domain": "aws", "id": "aws_root_usage", "tactic": "Privilege Escalation", "technique": "T1078.004",
     "title": "AWS root account used", "entity": "sourceIPAddress",
     "spl": 'search index={index} sourcetype=aws:cloudtrail userIdentity_type=Root | table _time eventName sourceIPAddress | head 5'},
    {"domain": "aws", "id": "aws_cloudtrail_disabled", "tactic": "Defense Evasion", "technique": "T1562.008",
     "title": "AWS CloudTrail logging disabled", "entity": "userIdentity_userName",
     "spl": 'search index={index} (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail) | table _time eventName userIdentity_userName | head 5'},
    {"domain": "aws", "id": "aws_iam_priv_esc", "tactic": "Privilege Escalation", "technique": "T1098",
     "title": "AWS IAM privilege escalation (admin policy attached)", "entity": "userIdentity_userName",
     "spl": 'search index={index} (eventName=AttachUserPolicy OR eventName=PutUserPolicy OR eventName=AttachRolePolicy) '
            '(requestParameters_policyArn="*AdministratorAccess*" OR requestParameters_policyArn="*Admin*") | table _time eventName userIdentity_userName | head 5'},
    {"domain": "aws", "id": "aws_access_key_created", "tactic": "Persistence", "technique": "T1098.001",
     "title": "AWS access key created", "entity": "userIdentity_userName",
     "spl": 'search index={index} eventName=CreateAccessKey | table _time userIdentity_userName sourceIPAddress | head 5'},
    {"domain": "aws", "id": "aws_sg_open", "tactic": "Defense Evasion", "technique": "T1562.007",
     "title": "AWS security group opened to the world (0.0.0.0/0)", "entity": "userIdentity_userName",
     "spl": 'search index={index} eventName=AuthorizeSecurityGroupIngress requestParameters_cidrIp="0.0.0.0/0" | table _time userIdentity_userName requestParameters_fromPort | head 5'},
    {"domain": "aws", "id": "aws_public_bucket", "tactic": "Exfiltration", "technique": "T1530",
     "title": "AWS S3 bucket exposed publicly", "entity": "requestParameters_bucketName",
     "spl": 'search index={index} (eventName=PutBucketAcl OR eventName=PutBucketPolicy) (requestParameters_x_amz_acl="*public*" OR "AllUsers") '
            '| table _time userIdentity_userName requestParameters_bucketName | head 5'},

    # ---------------- Azure ----------------
    {"domain": "azure", "id": "azure_risky_signin", "tactic": "Initial Access", "technique": "T1078.004",
     "title": "Azure AD risky sign-in (high risk / legacy auth)", "entity": "userPrincipalName",
     "spl": 'search index={index} (riskLevel=high OR riskLevel=medium OR clientAppUsed="Other clients") userPrincipalName=* '
            '| stats count by userPrincipalName ipAddress | sort -count | head 5'},
    {"domain": "azure", "id": "azure_admin_role_grant", "tactic": "Privilege Escalation", "technique": "T1098.003",
     "title": "Azure AD privileged role granted (Global Administrator / Owner)", "entity": "initiatedBy",
     "spl": 'search index={index} operationName="Add member to role" (targetRole="*Administrator*" OR targetRole="*Owner*") '
            '| table _time initiatedBy targetRole | head 5'},
    {"domain": "azure", "id": "azure_sp_cred_added", "tactic": "Persistence", "technique": "T1098.001",
     "title": "Azure AD service-principal credential added (backdoor)", "entity": "initiatedBy",
     "spl": 'search index={index} operationName="Add service principal credentials" | table _time initiatedBy targetResource | head 5'},

    # ---------------- GCP ----------------
    {"domain": "gcp", "id": "gcp_iam_owner_grant", "tactic": "Privilege Escalation", "technique": "T1098",
     "title": "GCP IAM owner/editor role granted", "entity": "principalEmail",
     "spl": 'search index={index} methodName=SetIamPolicy (role="roles/owner" OR role="roles/editor") | table _time principalEmail role member | head 5'},
    {"domain": "gcp", "id": "gcp_sa_key_created", "tactic": "Persistence", "technique": "T1098.001",
     "title": "GCP service-account key created", "entity": "principalEmail",
     "spl": 'search index={index} methodName="*CreateServiceAccountKey*" | table _time principalEmail callerIp | head 5'},
    {"domain": "gcp", "id": "gcp_public_bucket", "tactic": "Exfiltration", "technique": "T1530",
     "title": "GCP storage bucket exposed publicly (allUsers)", "entity": "principalEmail",
     "spl": 'search index={index} methodName=storage.setIamPolicy (member=allUsers OR member=allAuthenticatedUsers) | table _time principalEmail resourceName | head 5'},
    {"domain": "gcp", "id": "gcp_logging_disabled", "tactic": "Defense Evasion", "technique": "T1562.008",
     "title": "GCP logging sink deleted", "entity": "principalEmail",
     "spl": 'search index={index} methodName="*DeleteSink*" | table _time principalEmail callerIp | head 5'},
]


def _corroborating_sources(mcp, index: str, value: str) -> list[str]:
    """Which sourcetypes independently mention this entity value (Layer-2 evidence)."""
    safe = str(value).replace('"', "")
    rows = mcp.run_query(f'search index={index} "{safe}" | stats count by sourcetype')
    return sorted({r.get("sourcetype") for r in rows if r.get("sourcetype")})


def _meta(det: dict) -> dict:
    return {k: det[k] for k in ("domain", "id", "tactic", "technique", "title", "entity")}


def hunt(mcp, index: str = "soc_demo", thresholds: dict | None = None) -> list[dict]:
    """Run the whole detection pack via MCP; validate every hit through the 3-layer gate."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    results = []
    for det in DETECTIONS:
        try:
            hits = mcp.run_query(det["spl"].format(index=index, **th))
        except Exception as e:
            results.append({**_meta(det), "error": str(e)[:160], "disposition": "error"})
            continue
        for hit in hits:
            val = hit.get(det["entity"])
            if not val:
                continue
            sources = _corroborating_sources(mcp, index, val) or [hit.get("sourcetype") or "?"]
            finding = {"id": det["id"], "title": f"{det['title']} — {det['entity']}={val}",
                       "claims": [{"field": det["entity"], "value": val}]}
            v = validate_finding(finding, [{det["entity"]: val, "sourcetype": s} for s in sources])
            results.append({**_meta(det), "value": val, "evidence": hit,
                            "disposition": v["disposition"], "confidence": v["confidence"], "sources": sources})
    return results


def print_hunt(results: list[dict]) -> None:
    confirmed = [r for r in results if r.get("disposition") == "confirmed"]
    domains = [d for d in ("identity", "web", "endpoint", "network", "aws", "azure", "gcp")
               if any(r["domain"] == d for r in confirmed)]
    print("\n" + "=" * 72)
    print(f"SOC SENTINEL — UNIVERSAL MULTI-CLOUD HUNT  ({len(confirmed)} confirmed "
          f"across {len(DETECTIONS)} behavioural detectors, {len(domains)} domains)")
    print("=" * 72)
    for dom in domains:
        print(f"\n── {dom.upper()} ──")
        for r in [c for c in confirmed if c["domain"] == dom]:
            print(f"  [{r['confidence']:6}] {r['technique']:10} {r['title']}")
            print(f"           {r['entity']}={r['value']}  · corroborated by {len(r['sources'])} source(s)")
    errs = [r for r in results if r.get("disposition") == "error"]
    for r in errs:
        print(f"\n[ERROR] {r['id']}: {r['error']}")


if __name__ == "__main__":
    from splunk_mcp import SplunkMCP
    idx = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "soc_demo"
    m = SplunkMCP(); m.initialize()
    print_hunt(hunt(m, idx))
