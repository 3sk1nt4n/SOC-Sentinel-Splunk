# Top-5 advanced attacks SOC Sentinel finds

Each case is detected by **universal behaviour** (no hardcoded IOCs), mapped to MITRE
ATT&CK, and — crucially — every claim is **traced to a real Splunk row** before it's
reported, with confidence set by how many *independent data sources* corroborate it.
All of these fire on the reproducible demo (`python3 src/seed_demo_index.py --reset`);
the detectors live in `src/detections.py`.

---

## 1 · Full multi-stage account compromise → lateral movement (the flagship)
**Story:** an external IP brute-forces a service account, succeeds, escalates
privileges, dumps credentials, runs discovery, then moves laterally across the estate.

| Stage | Detector | MITRE |
|---|---|---|
| Brute force → breach | `brute_force` | T1110 |
| Privilege escalation | `sensitive_privilege` (SeDebug/SeTcb) | T1078 / 4672 |
| Credential dumping | `credential_dump` (SAM hive / LSASS minidump) | T1003 |
| Discovery burst | `recon_burst` (net/systeminfo/nltest) | T1087 |
| Lateral movement | `psexec_lateral` (PSEXESVC+admin share), `rdp_lateral` (Type-10) | T1021.002 / .001 |

**Why it's high-confidence:** the same compromised account appears across `linux_secure`,
`windows:security`, `cisco:asa` and Sysmon → **3+ independent sources → HIGH risk**.

## 2 · Memory-injection / process hollowing (fileless, "deep memory" footprint)
**Story:** a malicious document spawns encoded PowerShell that injects into a live
process, hollows a system binary, and reflectively loads a DLL — fileless post-exploitation.

| Signal | Detector | MITRE |
|---|---|---|
| Office → shell | `office_spawns_shell` | T1059 |
| Encoded PowerShell | `encoded_powershell` | T1059.001 |
| Code injection | `process_injection` (Sysmon EID 8 CreateRemoteThread / EID 10 RWX access) | T1055 |
| Process hollowing | `process_hollowing` (Sysmon EID 25 ProcessTampering) | T1055.012 |
| Reflective DLL | `reflective_dll_load` (unsigned DLL from temp) | T1055.001 |
| LSASS access | `lsass_access` | T1003.001 |

> These are the **log-native equivalents** of Volatility `malfind`/`hollowprocess` — the
> *runtime footprint* of injection/hollowing as it lands in Sysmon, which is how a SOC
> catches these without a memory image.

## 3 · Rootkit / kernel-driver persistence
**Story:** the attacker installs a kernel-mode driver service from a temp directory and
runs a system binary from a non-standard path to hide.

| Signal | Detector | MITRE |
|---|---|---|
| Service from temp path (kernel-mode driver) | `service_from_temp` (Event 7045) | T1543.003 |
| System-process masquerade | `process_masquerade` (svchost/lsass from non-System32) | T1036.005 |

## 4 · Cloud account takeover & cross-cloud abuse (AWS + Azure + GCP)
**Story:** one identity is compromised and abused across all three clouds — risky
sign-ins, privilege escalation, backdoor credentials, public buckets, logging disabled.

| Cloud | Detectors | MITRE |
|---|---|---|
| Identity | `azure_risky_signin`, `cloud_login_failures` | T1078.004 / T1110.004 |
| AWS | `aws_root_usage`, `aws_iam_priv_esc`, `aws_access_key_created`, `aws_cloudtrail_disabled`, `aws_sg_open`, `aws_public_bucket` | T1078 / T1098 / T1562 / T1530 |
| Azure | `azure_admin_role_grant`, `azure_sp_cred_added` | T1098.003 / .001 |
| GCP | `gcp_iam_owner_grant`, `gcp_sa_key_created`, `gcp_public_bucket`, `gcp_logging_disabled` | T1098 / T1530 / T1562.008 |

**Why it's high-confidence:** the **same identity corroborated across AWS, Azure and GCP**
→ a cross-cloud attack that single-cloud tools miss.

## 5 · Data theft + anti-forensics + ransomware prep (impact)
**Story:** the attacker exfiltrates data over DNS and to a public bucket, securely wipes
its tools, clears the logs, then deletes shadow copies to set up ransomware.

| Signal | Detector | MITRE |
|---|---|---|
| DNS tunnelling exfil | `dns_tunneling` | T1071.004 |
| Large egress | `data_exfil` (volume outlier) | T1567 |
| Public cloud bucket | `aws_public_bucket` / `gcp_public_bucket` | T1530 |
| Secure-wipe anti-forensics | `antiforensics_deletion` (sdelete/cipher) | T1070.004 |
| Log clearing | `log_cleared` (Event 1102) | T1070.001 |
| Ransomware prep | `ransomware_prep` (vssadmin delete shadows + bcdedit) | T1490 |

---

In every case, the AI proposes the finding and **code checks it**: anything the data
can't support is blocked (the report's "Blocked by the validator" section), and
confidence is earned by corroboration — so what reaches the analyst is trustworthy.
