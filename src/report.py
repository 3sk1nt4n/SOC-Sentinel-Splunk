"""Reporting for SOC Sentinel — executive summary, MITRE ATT&CK matrix, a findings
table, remediations, and the re-runnable SPL that proves each finding. Renders both
Markdown and a styled, self-contained HTML report.

Splunk-native touches vs a generic report: every confirmed finding carries the exact
SPL an analyst can paste back into Splunk to reproduce it, the data source(s) that
corroborate it, and a code-assigned confidence — so the report is auditable end to end.

Pure function of the hunt results (+ detector metadata); no network; never raises."""
from __future__ import annotations

import html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detections import DEFAULT_THRESHOLDS, DETECTIONS  # noqa: E402

_TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                 "Defense Evasion", "Credential Access", "Lateral Movement",
                 "Command and Control", "Exfiltration"]
_SPL_BY_ID = {d["id"]: d["spl"] for d in DETECTIONS}

# Universal remediation guidance per detector (no case-specific values).
REMEDIATIONS = {
    "brute_force": "Block/rate-limit the source IP; reset the targeted credentials; enforce MFA; investigate any successful login that followed the burst.",
    "password_spray": "Enforce MFA and account-lockout thresholds; review every targeted account; block the source.",
    "cloud_login_failures": "Require MFA; restrict console access by SSO/IP allow-list; review IAM activity for the targeted identity.",
    "web_attack": "Patch the vulnerable endpoint and front it with a WAF; check for successful exploitation (2xx after probes); rotate any exposed secrets.",
    "encoded_powershell": "Enable PowerShell script-block + module logging; isolate the host; hunt for the downloaded payload; reset local credentials.",
    "office_spawns_shell": "Deploy ASR rules to block Office child processes; quarantine the document; isolate the host.",
    "lolbin_download": "Alert/block LOLBin network egress; inspect the downloaded artifact; isolate the host.",
    "lsass_access": "Treat as credential theft: reset ALL credentials used on the host, enable Credential Guard / LSA protection, isolate immediately.",
    "registry_runkey": "Remove the Run-key value; identify and analyse the referenced binary; isolate the host.",
    "scheduled_task": "Disable/remove the task; identify its action; watch for re-creation (persistence).",
    "service_from_temp": "Stop and remove the service/driver; treat as possible rootkit (reimage if kernel-mode); preserve the binary for analysis.",
    "defender_tamper": "Re-enable endpoint protection; treat the host as compromised; investigate everything that ran while it was disabled.",
    "sensitive_privilege": "Review why the account holds SeDebug/SeTcb/SeLoadDriver; revoke if unwarranted; investigate subsequent actions.",
    "log_cleared": "Treat as active intrusion (anti-forensics); preserve remaining logs to immutable storage; isolate the host.",
    "lateral_movement": "Disable and reset the account; review every host it reached; tighten network segmentation.",
    "beaconing": "Block the destination at the egress gateway; isolate the beaconing host; identify and remove the implant.",
    "dns_tunneling": "Block the resolver/parent domain; isolate the host; inspect for data staged for exfiltration.",
    "data_exfil": "Block the destination; assess what data was exposed; engage IR/legal for breach handling; preserve evidence.",
    "aws_root_usage": "Stop using root; enable hardware MFA on root; operate via scoped IAM roles; review CloudTrail for all root actions.",
    "aws_cloudtrail_disabled": "Re-enable CloudTrail with log-file validation; alert on StopLogging/DeleteTrail; review the blind-spot window.",
    "aws_iam_priv_esc": "Detach the admin policy; review the principal's recent API calls; rotate its access keys.",
    "aws_access_key_created": "Confirm the key was authorised; disable/rotate if not; alert on CreateAccessKey going forward.",
    "aws_sg_open": "Restrict the security group to required CIDRs; audit resources that were exposed; alert on 0.0.0.0/0 ingress.",
    "aws_public_bucket": "Make the bucket private; enable S3 Block Public Access account-wide; review access logs for exposure.",
    "azure_risky_signin": "Enforce Conditional Access + MFA; block legacy authentication; revoke the identity's sessions.",
    "azure_admin_role_grant": "Verify the role grant; remove if unauthorised; require PIM/approval for privileged roles.",
    "azure_sp_cred_added": "Remove the added credential (likely backdoor); review the app's API permissions and consent grants.",
    "gcp_iam_owner_grant": "Remove the owner/editor binding; apply least privilege; alert on SetIamPolicy for primitive roles.",
    "gcp_sa_key_created": "Validate or disable the key; prefer Workload Identity over keys; alert on key creation.",
    "gcp_public_bucket": "Remove allUsers/allAuthenticatedUsers; enforce public-access prevention; review object access.",
    "gcp_logging_disabled": "Recreate the logging sink; alert on sink deletion; review the blind-spot window.",
}

_SEV = {"HIGH": ("🔴", "act now"), "MEDIUM": ("🟠", "investigate"), "LOW": ("🟡", "review")}


def _confirmed(results):
    return [r for r in results if r.get("disposition") == "confirmed"]


def _spl(det_id, index="soc_demo"):
    try:
        return _SPL_BY_ID[det_id].format(index=index, **DEFAULT_THRESHOLDS)
    except Exception:
        return _SPL_BY_ID.get(det_id, "")


def _ordered(confirmed):
    rank = {t: i for i, t in enumerate(_TACTIC_ORDER)}
    conf_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(confirmed, key=lambda r: (rank.get(r["tactic"], 99), conf_rank.get(r["confidence"], 9)))


def build_markdown(results, index="soc_demo") -> str:
    c = _ordered(_confirmed(results))
    techniques = sorted({r["technique"] for r in c})
    tactics = [t for t in _TACTIC_ORDER if any(r["tactic"] == t for r in c)]
    sources = sorted({s for r in c for s in r.get("sources", [])})
    highs = [r for r in c if r["confidence"] == "HIGH"]

    L = ["# 🛡️ SOC Sentinel — Incident Report", ""]
    L.append("## Executive summary")
    L.append("")
    L.append(f"SOC Sentinel autonomously investigated `index={index}` and confirmed "
             f"**{len(c)} findings** spanning **{len(techniques)} MITRE ATT&CK techniques** "
             f"across **{len(tactics)} tactics** and **{len(sources)} data sources**. "
             f"**{len(highs)} are HIGH confidence** (corroborated by ≥3 independent sources). "
             "Every finding below is backed by a real Splunk search result — claims the data "
             "could not support were blocked by the validator and are not reported as fact.")
    L.append("")
    if c:
        L.append(f"**Assessment:** the evidence describes a multi-stage intrusion — "
                 f"{' → '.join(tactics)}. Treat as an active incident.")
        L.append("")

    L.append("## MITRE ATT&CK coverage")
    L.append("")
    L.append("| Tactic | Techniques confirmed |")
    L.append("|---|---|")
    for t in tactics:
        techs = sorted({f"{r['technique']}" for r in c if r["tactic"] == t})
        L.append(f"| {t} | {', '.join(techs)} |")
    L.append("")

    L.append("## Confirmed findings")
    L.append("")
    L.append("| Sev | Confidence | Technique | Finding | Entity | Corroboration |")
    L.append("|---|---|---|---|---|---|")
    for r in c:
        sev = _SEV.get(r["confidence"], ("", ""))[0]
        L.append(f"| {sev} | {r['confidence']} | {r['technique']} | {r['title']} | "
                 f"`{r['entity']}={r['value']}` | {len(r.get('sources', []))} source(s) |")
    L.append("")

    L.append("## Remediation & reproduction")
    L.append("")
    seen = set()
    for r in c:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        L.append(f"### {r['technique']} — {r['title']}")
        L.append(f"- **Remediation:** {REMEDIATIONS.get(r['id'], 'Investigate and contain per IR playbook.')}")
        L.append(f"- **Reproduce in Splunk:**")
        L.append(f"  ```spl\n  {_spl(r['id'], index)}\n  ```")
        L.append("")

    L.append("---")
    L.append("*Generated by SOC Sentinel. The agent reaches Splunk only through the Splunk "
             "MCP Server (read-only search); a deterministic 3-layer validator confirms every "
             "claim against real result rows before it appears here.*")
    return "\n".join(L) + "\n"


_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1a1a1a}
.wrap{max-width:980px;margin:0 auto;padding:32px}
h1{color:#1a4971;border-bottom:4px solid #65A637;padding-bottom:10px}
h2{color:#1a4971;margin-top:34px}
.sum{background:#eaf1fb;border-left:5px solid #2b6cb0;padding:16px 18px;border-radius:6px}
table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th{background:#1a4971;color:#fff;text-align:left;padding:9px 11px;font-size:14px}
td{padding:9px 11px;border-top:1px solid #e3e8ee;font-size:14px;vertical-align:top}
tr:nth-child(even) td{background:#fafbfc}
.chip{display:inline-block;padding:2px 9px;border-radius:11px;font-size:12px;font-weight:600;color:#fff}
.HIGH{background:#c0392b}.MEDIUM{background:#e08e0b}.LOW{background:#7a8b99}
code,pre{font-family:SFMono-Regular,Consolas,monospace}
pre{background:#0e2c45;color:#d7e6f5;padding:12px 14px;border-radius:6px;overflow-x:auto;font-size:13px}
.rem{background:#fff;border:1px solid #e3e8ee;border-radius:8px;padding:14px 16px;margin:12px 0}
.foot{margin-top:30px;color:#5a6b7a;font-size:13px;border-top:1px solid #dde3ea;padding-top:14px}
.mtag{display:inline-block;background:#65A637;color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;margin:1px}
"""


def build_html(results, index="soc_demo") -> str:
    c = _ordered(_confirmed(results))
    techniques = sorted({r["technique"] for r in c})
    tactics = [t for t in _TACTIC_ORDER if any(r["tactic"] == t for r in c)]
    sources = sorted({s for r in c for s in r.get("sources", [])})
    highs = [r for r in c if r["confidence"] == "HIGH"]
    e = html.escape

    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>SOC Sentinel — Incident Report</title><style>{_CSS}</style></head><body><div class='wrap'>"]
    h.append("<h1>🛡️ SOC Sentinel — Incident Report</h1>")
    h.append("<h2>Executive summary</h2><div class='sum'>")
    h.append(f"<p>SOC Sentinel autonomously investigated <code>index={e(index)}</code> and confirmed "
             f"<b>{len(c)} findings</b> spanning <b>{len(techniques)} MITRE ATT&amp;CK techniques</b> across "
             f"<b>{len(tactics)} tactics</b> and <b>{len(sources)} data sources</b>. "
             f"<b>{len(highs)} are HIGH confidence</b> (≥3 independent sources). Every finding is backed by a "
             "real Splunk result; unsupported claims were blocked by the validator.</p>")
    if tactics:
        h.append(f"<p><b>Assessment:</b> multi-stage intrusion — {' &rarr; '.join(e(t) for t in tactics)}. "
                 "Treat as an active incident.</p>")
    h.append("</div>")

    h.append("<h2>MITRE ATT&CK coverage</h2><table><tr><th>Tactic</th><th>Techniques confirmed</th></tr>")
    for t in tactics:
        techs = sorted({r["technique"] for r in c if r["tactic"] == t})
        h.append(f"<tr><td>{e(t)}</td><td>{''.join(f'<span class=mtag>{e(x)}</span>' for x in techs)}</td></tr>")
    h.append("</table>")

    h.append("<h2>Confirmed findings</h2><table>"
             "<tr><th>Confidence</th><th>Technique</th><th>Finding</th><th>Entity</th><th>Corroboration</th></tr>")
    for r in c:
        h.append(f"<tr><td><span class='chip {e(r['confidence'])}'>{e(r['confidence'])}</span></td>"
                 f"<td>{e(r['technique'])}</td><td>{e(r['title'])}</td>"
                 f"<td><code>{e(r['entity'])}={e(str(r['value']))}</code></td>"
                 f"<td>{len(r.get('sources', []))} source(s)</td></tr>")
    h.append("</table>")

    h.append("<h2>Remediation &amp; reproduction</h2>")
    seen = set()
    for r in c:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        h.append("<div class='rem'>")
        h.append(f"<b>{e(r['technique'])} — {e(r['title'])}</b>"
                 f"<p>{e(REMEDIATIONS.get(r['id'], 'Investigate and contain per IR playbook.'))}</p>"
                 f"<p><i>Reproduce in Splunk:</i></p><pre>{e(_spl(r['id'], index))}</pre></div>")

    h.append("<div class='foot'>Generated by SOC Sentinel. The agent reaches Splunk only through the "
             "<b>Splunk MCP Server</b> (read-only search); a deterministic 3-layer validator confirms every "
             "claim against real result rows before it appears here.</div>")
    h.append("</div></body></html>")
    return "".join(h)


def write_reports(results, index="soc_demo", outdir="reports") -> dict:
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "incident_report.md")
    html_path = os.path.join(outdir, "incident_report.html")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(build_markdown(results, index))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html(results, index))
    return {"markdown": md_path, "html": html_path}
