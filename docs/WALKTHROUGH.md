# Walkthrough - the #1 alert, step by step (real output)

**Alert:** multi-stage account compromise → lateral movement (the flagship case from
[`CASES.md`](CASES.md)). Everything below is **real output** from the reproducible demo
(`python3 src/seed_demo_index.py --reset`), pulled live through the Splunk MCP Server.
Detection is universal - the SPL never hardcodes an IOC; we *pivot* on what each step finds.

> Run it yourself any of three ways:
> - `./soc-sentinel.sh` → choose **2** (the hunt finds this + 40 more, free), or
> - paste each SPL below into **Splunk Web** (`http://localhost:8000` → Search, *Last 24h*), or
> - `python3 src/agent.py "Find the full intrusion in index=soc_demo: brute force, lateral movement, persistence, exfiltration."`

---

### Step 1 · Initial Access (T1110) - who is hammering us?
```spl
index=soc_demo (action=failure OR EventCode=4625)
| stats count as failures dc(user) as users_targeted by src_ip | where failures>=10 | sort -failures
```
```
{'src_ip': '203.0.113.66', 'failures': '65', 'users_targeted': '1'}
```
→ one external IP, **65 failed logins** against a single account.

### Step 2 · (T1078) - the same IP then SUCCEEDS
```spl
index=soc_demo action=success src_ip=203.0.113.66 | stats count by user src_ip dest_host
```
```
{'user': 'svc_backup', 'src_ip': '203.0.113.66', 'dest_host': 'vpn01', 'count': '1'}
```
→ the brute force worked: **`svc_backup`** logged in from the attacker IP.

### Step 3 · Privilege Escalation (Event 4672) - sensitive privileges granted
```spl
index=soc_demo EventCode=4672 user=svc_backup | table user privileges
```
```
{'user': 'svc_backup', 'privileges': 'SeDebugPrivilege,SeTcbPrivilege'}
```

### Step 4 · Credential Access (T1003) - credential dumping
```spl
index=soc_demo (CommandLine="*reg* save*SAM*" OR CommandLine="*comsvcs*MiniDump*") | table host CommandLine
```
```
{'host': 'WIN-APP01', 'CommandLine': 'rundll32 comsvcs.dll MiniDump 612 C:\\Windows\\Temp\\l.dmp full'}
{'host': 'WIN-APP01', 'CommandLine': 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save'}
```

### Step 5 · Discovery (T1087) - recon burst
```spl
index=soc_demo EventCode=1 (CommandLine="*net view*" OR CommandLine="*systeminfo*" OR CommandLine="*tasklist*" OR CommandLine="*nltest*")
| stats dc(CommandLine) as recon_cmds values(CommandLine) as cmds by host
```
```
{'host': 'WIN-APP01', 'recon_cmds': '4', 'cmds': ['net view /domain', 'nltest /dclist:corp', 'systeminfo', 'tasklist /v']}
```

### Step 6 · Lateral Movement (T1021) - RDP + PsExec to internal hosts
```spl
index=soc_demo (EventCode=4624 LogonType=10) OR (EventCode=7045 service_name=PSEXESVC)
| table _time host EventCode user service_name
```
```
{'host': 'WIN-DB01',  'EventCode': '7045', 'service_name': 'PSEXESVC'}   ← PsExec
{'host': 'WIN-APP01', 'EventCode': '4624', 'user': 'svc_backup'}        ← RDP (Type 10)
```

### Step 7 · Corroboration - how many independent sources name the attacker?
```spl
index=soc_demo "203.0.113.66" | stats count by sourcetype
```
```
access_combined · aws:cloudtrail · azure:aad:signin · linux_secure · windows:security   (5 sources)
```

### Step 8 · The gate - code checks the finding
```
✅ CONFIRMED  [HIGH]  Account svc_backup compromised by external 203.0.113.66 (brute force → lateral)
      L1: 1/1 claims trace to real Splunk rows
      L2: 5 independent sources: access_combined, aws:cloudtrail, azure:aad:signin, linux_secure, windows:security

🚫 REJECTED  [NONE]  C2 beacon to 8.8.8.8 (model-invented)
      L1: 0/1 claims trace to real Splunk rows
```

---

## What this shows

The whole kill chain is reconstructed from **behaviour** (failure bursts, privilege
grants, dump commands, recon sequences, Type-10 logons, PSEXESVC) - no hardcoded IOCs.
The real attacker reaches **HIGH** confidence because **5 independent data sources**
corroborate it, while an invented finding is **blocked** by the validator. That's the
whole point: *the AI does the thinking; the code checks the facts.*
