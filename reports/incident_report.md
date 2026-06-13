# 🛡️ SOC Sentinel — Incident Report

_Scope: Universal hunt · `index=soc_demo`_

## Executive summary

SOC Sentinel confirmed **29 findings** spanning **23 MITRE ATT&CK techniques** across **9 tactics** and **11 data sources**; **11 are HIGH confidence**. Every confirmed finding is backed by a real Splunk search result.

**Assessment:** multi-stage intrusion — Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Lateral Movement → Command and Control → Exfiltration. Treat as an active incident.
**Highest risk:** Authentication brute force (failure burst from one source) — T1110 (risk 100/100, HIGH). Findings are ranked by risk = confidence × corroboration × tactic impact.

## MITRE ATT&CK coverage

| Tactic | Techniques confirmed |
|---|---|
| Initial Access | T1078.004, T1190 |
| Execution | T1059, T1059.001 |
| Persistence | T1053.005, T1098.001, T1543.003, T1547.001 |
| Privilege Escalation | T1078, T1078.004, T1098, T1098.003 |
| Defense Evasion | T1070.001, T1562.001, T1562.007, T1562.008 |
| Credential Access | T1003.001, T1110, T1110.004 |
| Lateral Movement | T1021 |
| Command and Control | T1071.004, T1105 |
| Exfiltration | T1530, T1567 |

## Confirmed findings — ranked by risk (highest first)

| Risk | Sev | Confidence | Technique | Finding | Entity | Corroboration |
|---:|---|---|---|---|---|---|
| 100 | 🔴 | HIGH | T1110 | Authentication brute force (failure burst from one source) | `src_ip=203.0.113.66` | 5 source(s) |
| 100 | 🔴 | HIGH | T1110.004 | Cloud console login failures from one source | `sourceIPAddress=203.0.113.66` | 5 source(s) |
| 100 | 🔴 | HIGH | T1071.004 | DNS tunnelling (many long unique subdomains) | `src_ip=10.10.0.42` | 6 source(s) |
| 99 | 🔴 | HIGH | T1078.004 | AWS root account used | `sourceIPAddress=203.0.113.66` | 5 source(s) |
| 97 | 🔴 | HIGH | T1190 | Web exploitation attempt (SQLi / path-traversal) | `src_ip=203.0.113.66` | 5 source(s) |
| 94 | 🔴 | HIGH | T1098 | AWS IAM privilege escalation (admin policy attached) | `userIdentity_userName=svc-deploy` | 4 source(s) |
| 93 | 🔴 | HIGH | T1098.001 | AWS access key created | `userIdentity_userName=svc-deploy` | 4 source(s) |
| 93 | 🔴 | HIGH | T1562.008 | AWS CloudTrail logging disabled | `userIdentity_userName=svc-deploy` | 4 source(s) |
| 93 | 🔴 | HIGH | T1562.007 | AWS security group opened to the world (0.0.0.0/0) | `userIdentity_userName=svc-deploy` | 4 source(s) |
| 89 | 🔴 | HIGH | T1078 | Sensitive privilege assignment (SeDebug / SeTcb / SeLoadDriver) | `user=svc_backup` | 3 source(s) |
| 89 | 🔴 | HIGH | T1021 | Lateral movement (one account into many hosts) | `user=svc_backup` | 3 source(s) |
| 61 | 🟠 | MEDIUM | T1567 | Large outbound transfer (egress-volume outlier) | `dest_ip=198.51.100.23` | 2 source(s) |
| 59 | 🟠 | MEDIUM | T1098.003 | Azure AD privileged role granted (Global Administrator / Owner) | `initiatedBy=svc-deploy@corp.com` | 2 source(s) |
| 58 | 🟠 | MEDIUM | T1098.001 | Azure AD service-principal credential added (backdoor) | `initiatedBy=svc-deploy@corp.com` | 2 source(s) |
| 57 | 🟠 | MEDIUM | T1078.004 | Azure AD risky sign-in (high risk / legacy auth) | `userPrincipalName=svc-deploy@corp.com` | 2 source(s) |
| 31 | 🟡 | LOW | T1530 | AWS S3 bucket exposed publicly | `requestParameters_bucketName=corp-backups-prod` | 1 source(s) |
| 31 | 🟡 | LOW | T1530 | GCP storage bucket exposed publicly (allUsers) | `principalEmail=svc-deploy@corp.iam.gserviceaccount.com` | 1 source(s) |
| 30 | 🟡 | LOW | T1003.001 | LSASS memory access (credential dumping) | `host=WIN-APP01` | 1 source(s) |
| 30 | 🟡 | LOW | T1105 | LOLBin used to download a payload (certutil/bitsadmin/mshta) | `host=WIN-APP01` | 1 source(s) |
| 29 | 🟡 | LOW | T1098 | GCP IAM owner/editor role granted | `principalEmail=svc-deploy@corp.iam.gserviceaccount.com` | 1 source(s) |
| 28 | 🟡 | LOW | T1547.001 | Run-key registry persistence | `host=WIN-APP01` | 1 source(s) |
| 28 | 🟡 | LOW | T1053.005 | Scheduled task created | `host=WIN-DC01` | 1 source(s) |
| 28 | 🟡 | LOW | T1543.003 | Service installed from a temp / user-writable path (possible rootkit) | `service_name=WinDefendUpd` | 1 source(s) |
| 28 | 🟡 | LOW | T1098.001 | GCP service-account key created | `principalEmail=svc-deploy@corp.iam.gserviceaccount.com` | 1 source(s) |
| 28 | 🟡 | LOW | T1562.001 | Endpoint protection tampering (Defender disabled) | `host=WIN-APP01` | 1 source(s) |
| 28 | 🟡 | LOW | T1070.001 | Security / audit log cleared (anti-forensics) | `host=WIN-DC01` | 1 source(s) |
| 28 | 🟡 | LOW | T1562.008 | GCP logging sink deleted | `principalEmail=svc-deploy@corp.iam.gserviceaccount.com` | 1 source(s) |
| 27 | 🟡 | LOW | T1059.001 | Obfuscated / encoded PowerShell execution | `host=WIN-APP01` | 1 source(s) |
| 27 | 🟡 | LOW | T1059 | Office application spawned a shell / script interpreter | `host=WIN-APP01` | 1 source(s) |

## Remediation & reproduction

### T1110 — Authentication brute force (failure burst from one source)
- **Remediation:** Block/rate-limit the source IP; reset the targeted credentials; enforce MFA; investigate any successful login that followed the burst.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (action=failure OR action=failed OR EventCode=4625 OR "failed password") src_ip=* | stats count as failures dc(user) as users by src_ip | where failures>=10 | sort -failures | head 5
  ```

### T1110.004 — Cloud console login failures from one source
- **Remediation:** Require MFA; restrict console access by SSO/IP allow-list; review IAM activity for the targeted identity.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo eventName=ConsoleLogin errorMessage="*Failed*" | stats count as failures by sourceIPAddress | where failures>=5 | sort -failures | head 5
  ```

### T1071.004 — DNS tunnelling (many long unique subdomains)
- **Remediation:** Block the resolver/parent domain; isolate the host; inspect for data staged for exfiltration.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (sourcetype=stream:dns OR query=*) query=* | eval _ql=len(query) | stats max(_ql) as longest dc(query) as uniq_subdomains by src_ip | where longest>40 AND uniq_subdomains>=10 | sort -uniq_subdomains | head 5
  ```

### T1078.004 — AWS root account used
- **Remediation:** Stop using root; enable hardware MFA on root; operate via scoped IAM roles; review CloudTrail for all root actions.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo sourcetype=aws:cloudtrail userIdentity_type=Root | table _time eventName sourceIPAddress | head 5
  ```

### T1190 — Web exploitation attempt (SQLi / path-traversal)
- **Remediation:** Patch the vulnerable endpoint and front it with a WAF; check for successful exploitation (2xx after probes); rotate any exposed secrets.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (uri="*%27*" OR uri="*'*" OR uri="*../*" OR uri="*UNION*" OR uri="*etc/passwd*") src_ip=* | stats count as hits by src_ip | where hits>=1 | sort -hits | head 5
  ```

### T1098 — AWS IAM privilege escalation (admin policy attached)
- **Remediation:** Detach the admin policy; review the principal's recent API calls; rotate its access keys.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (eventName=AttachUserPolicy OR eventName=PutUserPolicy OR eventName=AttachRolePolicy) (requestParameters_policyArn="*AdministratorAccess*" OR requestParameters_policyArn="*Admin*") | table _time eventName userIdentity_userName | head 5
  ```

### T1098.001 — AWS access key created
- **Remediation:** Confirm the key was authorised; disable/rotate if not; alert on CreateAccessKey going forward.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo eventName=CreateAccessKey | table _time userIdentity_userName sourceIPAddress | head 5
  ```

### T1562.008 — AWS CloudTrail logging disabled
- **Remediation:** Re-enable CloudTrail with log-file validation; alert on StopLogging/DeleteTrail; review the blind-spot window.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail) | table _time eventName userIdentity_userName | head 5
  ```

### T1562.007 — AWS security group opened to the world (0.0.0.0/0)
- **Remediation:** Restrict the security group to required CIDRs; audit resources that were exposed; alert on 0.0.0.0/0 ingress.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo eventName=AuthorizeSecurityGroupIngress requestParameters_cidrIp="0.0.0.0/0" | table _time userIdentity_userName requestParameters_fromPort | head 5
  ```

### T1078 — Sensitive privilege assignment (SeDebug / SeTcb / SeLoadDriver)
- **Remediation:** Review why the account holds SeDebug/SeTcb/SeLoadDriver; revoke if unwarranted; investigate subsequent actions.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo EventCode=4672 (privileges="*SeDebug*" OR privileges="*SeTcb*" OR privileges="*SeLoadDriver*" OR privileges="*SeBackup*") | table _time host user privileges | head 5
  ```

### T1021 — Lateral movement (one account into many hosts)
- **Remediation:** Disable and reset the account; review every host it reached; tighten network segmentation.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (action=success OR EventCode=4624) user=* (dest_host=* OR ComputerName=*) | eval _h=coalesce(dest_host,ComputerName) | stats dc(_h) as hosts values(_h) as host_list by user | where hosts>=3 | sort -hosts | head 5
  ```

### T1567 — Large outbound transfer (egress-volume outlier)
- **Remediation:** Block the destination; assess what data was exposed; engage IR/legal for breach handling; preserve evidence.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo bytes_out=* dest_ip=* | stats max(bytes_out) as max_out sum(bytes_out) as total_out by src_ip dest_ip | where max_out>=100000000 | sort -max_out | head 5
  ```

### T1098.003 — Azure AD privileged role granted (Global Administrator / Owner)
- **Remediation:** Verify the role grant; remove if unauthorised; require PIM/approval for privileged roles.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo operationName="Add member to role" (targetRole="*Administrator*" OR targetRole="*Owner*") | table _time initiatedBy targetRole | head 5
  ```

### T1098.001 — Azure AD service-principal credential added (backdoor)
- **Remediation:** Remove the added credential (likely backdoor); review the app's API permissions and consent grants.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo operationName="Add service principal credentials" | table _time initiatedBy targetResource | head 5
  ```

### T1078.004 — Azure AD risky sign-in (high risk / legacy auth)
- **Remediation:** Enforce Conditional Access + MFA; block legacy authentication; revoke the identity's sessions.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (riskLevel=high OR riskLevel=medium OR clientAppUsed="Other clients") userPrincipalName=* | stats count by userPrincipalName ipAddress | sort -count | head 5
  ```

### T1530 — AWS S3 bucket exposed publicly
- **Remediation:** Make the bucket private; enable S3 Block Public Access account-wide; review access logs for exposure.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (eventName=PutBucketAcl OR eventName=PutBucketPolicy) (requestParameters_x_amz_acl="*public*" OR "AllUsers") | table _time userIdentity_userName requestParameters_bucketName | head 5
  ```

### T1530 — GCP storage bucket exposed publicly (allUsers)
- **Remediation:** Remove allUsers/allAuthenticatedUsers; enforce public-access prevention; review object access.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo methodName=storage.setIamPolicy (member=allUsers OR member=allAuthenticatedUsers) | table _time principalEmail resourceName | head 5
  ```

### T1003.001 — LSASS memory access (credential dumping)
- **Remediation:** Treat as credential theft: reset ALL credentials used on the host, enable Credential Guard / LSA protection, isolate immediately.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo EventCode=10 TargetImage="*lsass*" | table _time host SourceImage TargetImage GrantedAccess | head 5
  ```

### T1105 — LOLBin used to download a payload (certutil/bitsadmin/mshta)
- **Remediation:** Alert/block LOLBin network egress; inspect the downloaded artifact; isolate the host.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (Image="*certutil*" OR Image="*bitsadmin*" OR Image="*mshta*") CommandLine="*http*" | table _time host Image CommandLine | head 5
  ```

### T1098 — GCP IAM owner/editor role granted
- **Remediation:** Remove the owner/editor binding; apply least privilege; alert on SetIamPolicy for primitive roles.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo methodName=SetIamPolicy (role="roles/owner" OR role="roles/editor") | table _time principalEmail role member | head 5
  ```

### T1547.001 — Run-key registry persistence
- **Remediation:** Remove the Run-key value; identify and analyse the referenced binary; isolate the host.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo EventCode=13 TargetObject="*CurrentVersion*Run*" | table _time host TargetObject Details | head 5
  ```

### T1053.005 — Scheduled task created
- **Remediation:** Disable/remove the task; identify its action; watch for re-creation (persistence).
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (EventCode=4698 OR CommandLine="*schtasks*create*" OR "scheduled task was created") | table _time host TaskName user | head 5
  ```

### T1543.003 — Service installed from a temp / user-writable path (possible rootkit)
- **Remediation:** Stop and remove the service/driver; treat as possible rootkit (reimage if kernel-mode); preserve the binary for analysis.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo EventCode=7045 (image_path="*Temp*" OR image_path="*AppData*" OR image_path="*ProgramData*" OR image_path="*\Users\*") | table _time host service_name image_path service_type | head 5
  ```

### T1098.001 — GCP service-account key created
- **Remediation:** Validate or disable the key; prefer Workload Identity over keys; alert on key creation.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo methodName="*CreateServiceAccountKey*" | table _time principalEmail callerIp | head 5
  ```

### T1562.001 — Endpoint protection tampering (Defender disabled)
- **Remediation:** Re-enable endpoint protection; treat the host as compromised; investigate everything that ran while it was disabled.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*Set-MpPreference*" OR CommandLine="*MpCmdRun*-removedefinitions*") | table _time host CommandLine | head 5
  ```

### T1070.001 — Security / audit log cleared (anti-forensics)
- **Remediation:** Treat as active intrusion (anti-forensics); preserve remaining logs to immutable storage; isolate the host.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (EventCode=1102 OR EventCode=104 OR "audit log was cleared" OR "wevtutil*cl") | table _time host user | head 5
  ```

### T1562.008 — GCP logging sink deleted
- **Remediation:** Recreate the logging sink; alert on sink deletion; review the blind-spot window.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo methodName="*DeleteSink*" | table _time principalEmail callerIp | head 5
  ```

### T1059.001 — Obfuscated / encoded PowerShell execution
- **Remediation:** Enable PowerShell script-block + module logging; isolate the host; hunt for the downloaded payload; reset local credentials.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*") | table _time host Image CommandLine User | head 5
  ```

### T1059 — Office application spawned a shell / script interpreter
- **Remediation:** Deploy ASR rules to block Office child processes; quarantine the document; isolate the host.
- **Reproduce in Splunk:**
  ```spl
  search index=soc_demo EventCode=1 (ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*outlook*") (Image="*powershell*" OR Image="*cmd.exe*" OR Image="*wscript*" OR Image="*mshta*") | table _time host ParentImage Image | head 5
  ```

---
*Generated by SOC Sentinel. The agent reaches Splunk only through the Splunk MCP Server (read-only search); a deterministic 3-layer validator confirms every claim against real result rows before it appears here.*
