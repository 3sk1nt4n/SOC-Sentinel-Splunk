# SOC Sentinel — Demo video script (≤ 3 minutes)

**Goal:** prove (1) Splunk AI used **at runtime** via the MCP Server, (2) the
anti-hallucination gate, (3) universal multi-cloud coverage, (4) clean reporting.
Record terminal + browser. Keep it fast; let the live output carry it.

**One-time setup (off-camera):** Splunk running with the MCP Server app installed;
`API_KEY.txt` has your key; `python3 src/seed_demo_index.py --reset` has populated `soc_demo`.

---

### Sec 1 — The problem (0:00 – 0:25)
**On screen:** title card → `docs/architecture.png`.
**Narration:** "Point an AI at your SIEM and it will confidently invent breaches that
aren't in your data. In a SOC, a confident wrong answer is worse than none. SOC Sentinel
fixes that: Claude investigates Splunk through the Splunk MCP Server, but **code, not the
model, decides what's confirmed** — every finding traces to a real Splunk result."

### Sec 2 — Live agentic investigation (0:25 – 1:15)
**Command:**
```bash
python3 src/agent.py "Investigate suspicious authentication, privilege escalation and outbound activity in index=soc_demo. Find the compromised account, the attacker, and any exfiltration."
```
**On screen:** the `🤖 model: claude-haiku-4-5` line, then the stream of `🔧 MCP call:
splunk_run_query(...)` and `🧠` reasoning steps scrolling.
**Narration:** "It's reasoning live — and every one of these searches is a real call to the
**Splunk MCP Server**. No mock data. It forms a hypothesis, queries Splunk, and refines —
dozens of tool calls, hundreds of real result rows."

### Sec 3 — The trust gate (1:15 – 2:00)
**On screen:** the printed report — the ✅ confirmed findings with `✓ in Splunk results`
traces, then the 🚫 **Blocked by the validator** lines.
**Narration:** "Here's the difference. Each confirmed finding's claims trace to real rows,
and confidence comes from how many **independent data sources** corroborate it — three or
more is HIGH. And here" — *(point at a blocked line)* — "is a claim the model asserted that
the data didn't support. The validator **blocked it**. That's what stops hallucinations from
ever reaching the report."
**Then open** `reports/incident_report.html`: scroll the exec summary → MITRE matrix →
risk-ranked table → per-finding remediation + the re-runnable SPL.
**Narration:** "And it writes an analyst-ready report — ranked by risk, MITRE-mapped, with the
exact SPL to reproduce each finding."

### Sec 4 — Universal & multi-cloud (2:00 – 2:40)
**Command:**
```bash
python3 src/agent.py --hunt
```
**On screen:** the hunt output grouped by domain — IDENTITY, ENDPOINT, NETWORK, AWS, AZURE, GCP.
**Narration:** "Beyond the agent, a library of **42 behavioural detectors across the full kill
chain and all three clouds** — AWS, Azure, GCP. None of them hardcode an IP or a username; they
detect *behaviour* — a failure burst, a periodic beacon, a service from a temp directory, an
owner-role grant. So they work on any environment, not just our demo. Notice the same identity
abused across AWS, Azure and GCP gets corroborated to HIGH."

### Sec 5 — Why it wins (2:40 – 3:00)
**On screen:** architecture diagram again / repo README.
**Narration:** "SOC Sentinel is the rare entry that actually uses Splunk's AI at runtime, with
a novel trust layer that makes agentic SOC analysis auditable — Security *and* a reusable harness
for the Splunk MCP Server. Code checks the AI. That's SOC Sentinel."

---

### Capture checklist
- [ ] Terminal font large; clear screen before each command.
- [ ] Show the `🔧 MCP call` lines (proves runtime Splunk AI use).
- [ ] Show at least one 🚫 blocked claim (the differentiator).
- [ ] Open the HTML report in a browser (the polish).
- [ ] Keep under 3:00; trim dead air in editing.
