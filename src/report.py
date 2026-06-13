"""Universal reporting for SOC Sentinel — one elegant engine for BOTH the
deterministic detection hunt and the live Claude investigation.

Everything renders from a single normalised record schema, so the same report
(executive summary · MITRE ATT&CK matrix · risk-ranked findings table · per-finding
remediation + the re-runnable SPL that proves it) is produced regardless of how the
findings were generated:

    record = {id, title, technique, tactic, confidence, disposition,
              sources[list], entity, value, reproduce_spl, remediation}

Adapters normalise each source:
    from_hunt(hunt_results, index)        # detector pack  -> records
    from_agent(investigation, index)      # Claude agent   -> records

Findings are ranked by a 0-100 risk score (confidence × corroboration × tactic
impact). Pure functions; no network; never raises. Renders Markdown + styled HTML."""
from __future__ import annotations

import html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detections import DEFAULT_THRESHOLDS, DETECTIONS  # noqa: E402

_TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                 "Defense Evasion", "Credential Access", "Lateral Movement",
                 "Command and Control", "Exfiltration", "Impact"]

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
_GENERIC_REM = "Investigate, contain the affected asset/identity, and follow the incident-response playbook for this technique."
# technique -> remediation, derived from the detector pack so Claude findings reuse it.
_REM_BY_TECH = {d["technique"]: REMEDIATIONS[d["id"]] for d in DETECTIONS if d["id"] in REMEDIATIONS}

_CONF_BASE = {"HIGH": 70, "MEDIUM": 45, "LOW": 20}
_IMPACT = {"Exfiltration": 6, "Impact": 6, "Command and Control": 5, "Credential Access": 5,
           "Lateral Movement": 4, "Privilege Escalation": 4, "Persistence": 3,
           "Defense Evasion": 3, "Execution": 2, "Initial Access": 2}
_SEV = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}


def _risk_score(r) -> int:
    base = _CONF_BASE.get(r.get("confidence"), 10)
    corr = 5 * min(len(r.get("sources") or []), 5)
    return min(100, base + corr + _IMPACT.get(r.get("tactic"), 1))


def _remediation_for(technique: str, det_id: str | None = None) -> str:
    if det_id and det_id in REMEDIATIONS:
        return REMEDIATIONS[det_id]
    return _REM_BY_TECH.get(technique) or _REM_BY_TECH.get((technique or "").split(".")[0]) or _GENERIC_REM


# ---------------------------------------------------------------- adapters
def from_hunt(results, index="soc_demo") -> list[dict]:
    out = []
    for r in results:
        if r.get("disposition") != "confirmed":
            out.append({**r, "sources": r.get("sources") or []})
            continue
        det_id = r.get("id")
        try:
            spl = next(d["spl"] for d in DETECTIONS if d["id"] == det_id).format(index=index, **DEFAULT_THRESHOLDS)
        except Exception:
            spl = ""
        out.append({"id": det_id, "title": r["title"], "technique": r["technique"], "tactic": r["tactic"],
                    "confidence": r["confidence"], "disposition": "confirmed", "sources": r.get("sources") or [],
                    "entity": r["entity"], "value": r["value"], "reproduce_spl": spl,
                    "remediation": _remediation_for(r["technique"], det_id)})
    return out


def from_agent(investigation, index="soc_demo") -> list[dict]:
    out = []
    for f in investigation.get("findings", []):
        claims = f.get("claims") or []
        supported = [c for c in claims if c.get("supported")]
        pick = (supported or claims or [{}])[0]
        ent, val = pick.get("field", ""), pick.get("value", "")
        tech = f.get("technique") or "—"
        out.append({"id": f.get("finding_id"), "title": f.get("title", ""),
                    "technique": tech, "tactic": f.get("tactic") or "—",
                    "confidence": f.get("confidence", "NONE"), "disposition": f.get("disposition"),
                    "sources": (f.get("layers") or {}).get("layer2_corroboration", {}).get("sources", []),
                    "entity": ent, "value": val,
                    "reproduce_spl": f'search index={index} {ent}="{val}"' if ent and val else "",
                    "remediation": _remediation_for(tech)})
    return out


# ---------------------------------------------------------------- ranking
def _confirmed(records):
    return [r for r in records if r.get("disposition") == "confirmed"]


def _blocked(records):
    return [r for r in records if r.get("disposition") in ("needs_review", "rejected")]


def _ordered(confirmed):
    rank = {t: i for i, t in enumerate(_TACTIC_ORDER)}
    return sorted(confirmed, key=lambda r: (-_risk_score(r), rank.get(r.get("tactic"), 99)))


# ---------------------------------------------------------------- markdown
def build_markdown(records, index="soc_demo", scope_label="investigation") -> str:
    c = _ordered(_confirmed(records))
    blocked = _blocked(records)
    techniques = sorted({r["technique"] for r in c if r["technique"] != "—"})
    tactics = [t for t in _TACTIC_ORDER if any(r.get("tactic") == t for r in c)]
    sources = sorted({s for r in c for s in (r.get("sources") or [])})
    highs = [r for r in c if r["confidence"] == "HIGH"]

    L = ["# 🛡️ SOC Sentinel — Incident Report", "", f"_Scope: {scope_label} · `index={index}`_", ""]
    L += ["## Executive summary", ""]
    L.append(f"SOC Sentinel confirmed **{len(c)} findings** spanning **{len(techniques)} MITRE ATT&CK "
             f"techniques** across **{len(tactics)} tactics** and **{len(sources)} data sources**; "
             f"**{len(highs)} are HIGH confidence**. "
             + (f"**{len(blocked)} model claim(s) were blocked/demoted by the validator** "
                "(unsupported by the data) and are not reported as fact. " if blocked else "")
             + "Every confirmed finding is backed by a real Splunk search result.")
    L.append("")
    if c:
        L.append(f"**Assessment:** multi-stage intrusion — {' → '.join(tactics)}. Treat as an active incident.")
        L.append(f"**Highest risk:** {c[0]['title']} — {c[0]['technique']} "
                 f"(risk {_risk_score(c[0])}/100, {c[0]['confidence']}). "
                 "Findings are ranked by risk = confidence × corroboration × tactic impact.")
        L.append("")

    if tactics:
        L += ["## MITRE ATT&CK coverage", "", "| Tactic | Techniques confirmed |", "|---|---|"]
        for t in tactics:
            techs = sorted({r["technique"] for r in c if r.get("tactic") == t and r["technique"] != "—"})
            L.append(f"| {t} | {', '.join(techs) or '—'} |")
        L.append("")

    L += ["## Confirmed findings — ranked by risk (highest first)", "",
          "| Risk | Sev | Confidence | Technique | Finding | Entity | Corroboration |",
          "|---:|---|---|---|---|---|---|"]
    for r in c:
        L.append(f"| {_risk_score(r)} | {_SEV.get(r['confidence'], '')} | {r['confidence']} | {r['technique']} | "
                 f"{r['title']} | `{r['entity']}={r['value']}` | {len(r.get('sources') or [])} source(s) |")
    L.append("")

    if blocked:
        L += ["## Blocked by the validator (unsupported claims)", "",
              "_These claims the model asserted but the Splunk data did not support — the gate kept them out of the findings:_", ""]
        for r in blocked:
            L.append(f"- {r['title']} — `{r['entity']}={r['value']}` ({r['disposition']})")
        L.append("")

    L += ["## Remediation & reproduction", ""]
    seen = set()
    for r in c:
        key = r.get("id") or r["technique"]
        if key in seen:
            continue
        seen.add(key)
        L.append(f"### {r['technique']} — {r['title']}")
        L.append(f"- **Remediation:** {r['remediation']}")
        if r.get("reproduce_spl"):
            L.append("- **Reproduce in Splunk:**")
            L.append(f"  ```spl\n  {r['reproduce_spl']}\n  ```")
        L.append("")

    L += ["---", "*Generated by SOC Sentinel. The agent reaches Splunk only through the Splunk MCP "
          "Server (read-only search); a deterministic 3-layer validator confirms every claim against "
          "real result rows before it appears here.*"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- html
_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1a1a1a}
.wrap{max-width:980px;margin:0 auto;padding:32px}
h1{color:#1a4971;border-bottom:4px solid #65A637;padding-bottom:10px}
h2{color:#1a4971;margin-top:34px}.muted{color:#5a6b7a;font-size:14px}
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
.blocked{background:#fff4f4;border-left:4px solid #c0392b;border-radius:6px;padding:10px 14px;margin:10px 0;font-size:14px}
.foot{margin-top:30px;color:#5a6b7a;font-size:13px;border-top:1px solid #dde3ea;padding-top:14px}
.mtag{display:inline-block;background:#65A637;color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;margin:1px}
"""


def build_html(records, index="soc_demo", scope_label="investigation") -> str:
    c = _ordered(_confirmed(records))
    blocked = _blocked(records)
    techniques = sorted({r["technique"] for r in c if r["technique"] != "—"})
    tactics = [t for t in _TACTIC_ORDER if any(r.get("tactic") == t for r in c)]
    sources = sorted({s for r in c for s in (r.get("sources") or [])})
    highs = [r for r in c if r["confidence"] == "HIGH"]
    e = html.escape

    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>SOC Sentinel — Incident Report</title><style>{_CSS}</style></head><body><div class='wrap'>"]
    h.append("<h1>🛡️ SOC Sentinel — Incident Report</h1>")
    h.append(f"<p class='muted'>Scope: {e(scope_label)} · <code>index={e(index)}</code></p>")
    h.append("<h2>Executive summary</h2><div class='sum'>")
    h.append(f"<p>Confirmed <b>{len(c)} findings</b> spanning <b>{len(techniques)} MITRE ATT&amp;CK techniques</b> "
             f"across <b>{len(tactics)} tactics</b> and <b>{len(sources)} data sources</b>; "
             f"<b>{len(highs)} are HIGH confidence</b>. "
             + (f"<b>{len(blocked)} model claim(s) were blocked/demoted by the validator</b> and are not reported as fact. "
                if blocked else "")
             + "Every confirmed finding is backed by a real Splunk result.</p>")
    if tactics:
        h.append(f"<p><b>Assessment:</b> multi-stage intrusion — {' &rarr; '.join(e(t) for t in tactics)}. Treat as active.</p>")
        h.append(f"<p><b>Highest risk:</b> {e(c[0]['title'])} — {e(c[0]['technique'])} (risk {_risk_score(c[0])}/100, "
                 f"{e(c[0]['confidence'])}). Findings ranked by risk = confidence × corroboration × tactic impact.</p>")
    h.append("</div>")

    if tactics:
        h.append("<h2>MITRE ATT&CK coverage</h2><table><tr><th>Tactic</th><th>Techniques confirmed</th></tr>")
        for t in tactics:
            techs = sorted({r["technique"] for r in c if r.get("tactic") == t and r["technique"] != "—"})
            h.append(f"<tr><td>{e(t)}</td><td>{''.join(f'<span class=mtag>{e(x)}</span>' for x in techs) or '—'}</td></tr>")
        h.append("</table>")

    h.append("<h2>Confirmed findings <span class='muted'>(ranked by risk, highest first)</span></h2><table>"
             "<tr><th>Risk</th><th>Confidence</th><th>Technique</th><th>Finding</th><th>Entity</th><th>Corroboration</th></tr>")
    for r in c:
        h.append(f"<tr><td><b>{_risk_score(r)}</b></td><td><span class='chip {e(r['confidence'])}'>{e(r['confidence'])}</span></td>"
                 f"<td>{e(r['technique'])}</td><td>{e(r['title'])}</td>"
                 f"<td><code>{e(r['entity'])}={e(str(r['value']))}</code></td><td>{len(r.get('sources') or [])} source(s)</td></tr>")
    h.append("</table>")

    if blocked:
        h.append("<h2>Blocked by the validator</h2>")
        for r in blocked:
            h.append(f"<div class='blocked'>🚫 <b>{e(r['title'])}</b> — <code>{e(r['entity'])}={e(str(r['value']))}</code> "
                     f"({e(r['disposition'])}): the model asserted this but the Splunk data did not support it.</div>")

    h.append("<h2>Remediation &amp; reproduction</h2>")
    seen = set()
    for r in c:
        key = r.get("id") or r["technique"]
        if key in seen:
            continue
        seen.add(key)
        spl = f"<p><i>Reproduce in Splunk:</i></p><pre>{e(r['reproduce_spl'])}</pre>" if r.get("reproduce_spl") else ""
        h.append(f"<div class='rem'><b>{e(r['technique'])} — {e(r['title'])}</b><p>{e(r['remediation'])}</p>{spl}</div>")

    h.append("<div class='foot'>Generated by SOC Sentinel. The agent reaches Splunk only through the "
             "<b>Splunk MCP Server</b> (read-only search); a deterministic 3-layer validator confirms every "
             "claim against real result rows before it appears here.</div></div></body></html>")
    return "".join(h)


def write_reports(records, index="soc_demo", scope_label="investigation", outdir="reports") -> dict:
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "incident_report.md")
    html_path = os.path.join(outdir, "incident_report.html")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(build_markdown(records, index, scope_label))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html(records, index, scope_label))
    return {"markdown": md_path, "html": html_path}
