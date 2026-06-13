# SOC Sentinel — Devpost submission

> **An agentic SOC analyst for Splunk that you can actually trust — because code, not the model, decides what's confirmed.**

**Track:** Security · **Splunk AI capability used at runtime:** the Splunk MCP Server (Splunkbase app 7931)

---

## Elevator pitch

Point an AI at your SIEM and ask *"was I breached?"* and it will confidently invent an
attacker IP, a hostname, a whole "confirmed" breach that isn't in your data. In security
that's a dealbreaker. **SOC Sentinel** lets Claude investigate Splunk freely through the
**Splunk MCP Server**, then runs every claim through a deterministic **3-layer validator**:
a finding is reported as fact only if it traces to a real Splunk search result. Anything
the AI can't prove is blocked before it reaches the analyst.

## Inspiration

We previously built an anti-hallucination DFIR agent for the SANS "Find Evil!" hackathon.
The single hardest, most valuable thing there was making an autonomous agent **trustworthy** —
provably grounded in evidence, never narrating a plausible story the data doesn't support.
Splunk's Agentic Ops hackathon is the perfect home for that idea: agentic AI over SIEM data
is enormously useful *and* enormously risky, and the thing standing between "cool demo" and
"production SOC tool" is trust. So we ported the trust core onto Splunk.

## What it does

1. An analyst asks a question in plain English.
2. **Claude** plans the investigation and runs SPL searches **through the Splunk MCP Server**
   (typed tools, read-only, no shell) — `splunk_run_query`, `splunk_get_indexes`, etc.
3. Claude drafts findings, each with explicit claims (`field = value`).
4. A **3-layer validator** gates every claim:
   - **L1 Trace** — the value must appear in a real Splunk result row, or it's dropped.
   - **L2 Corroboration** — how many independent sourcetypes back it.
   - **L3 Calibration** — confidence: 3+ sources = HIGH, 2 = MEDIUM, 1 = LOW.
5. The analyst gets a **risk-ranked incident report** (HTML + Markdown): executive summary,
   MITRE ATT&CK matrix, findings table, per-technique remediation, and **the exact SPL that
   reproduces each finding**. Unsupported claims appear in a "Blocked by the validator" section —
   proof the gate is working.

It ships two ways to run:
- **`--hunt`** — a universal, deterministic detection pack (no API key needed).
- **live agent** — Claude drives the whole investigation autonomously.

## How AI + Splunk are used (at runtime — not mocked, not planned)

- **Splunk AI capability:** the **Splunk MCP Server** is the agent's only channel to Splunk.
  Every search is a real `tools/call` over JSON-RPC to `/services/mcp`. Verified live: a Haiku
  investigation made **30+ MCP tool calls** and gathered **hundreds of real result rows**.
- **Reasoning:** Claude (Anthropic) forms hypotheses, chooses searches, and proposes findings.
- **The guardrail:** a deterministic Python validator — *the AI never gets to mark its own
  homework.*

## How we built it

- **`splunk_mcp.py`** — a stdlib MCP client: mints an `aud=mcp` token via `/services/mcp_token`,
  speaks MCP Streamable-HTTP JSON-RPC (`initialize` / `tools/list` / `tools/call`).
- **`finding_validator.py`** — the 3-layer trust pipeline.
- **`detections.py`** — **31 universal behavioural detectors across 7 domains** (identity,
  endpoint, network, AWS, Azure, GCP) mapped to MITRE ATT&CK. Every detector finds *behaviour
  or structure* — never a hardcoded IOC — so it survives a held-out environment (enforced by a
  "no answer keys" test).
- **`agent.py`** — the Claude tool-use loop + the deterministic gate demo.
- **`report.py`** — one universal reporting engine (risk-ranked HTML/Markdown) for both paths.
- **`seed_demo_index.py`** — a reproducible 6-sourcetype ATT&CK breach so judges can run the
  whole demo in two minutes without downloading a multi-GB dataset.

## Challenges

- **Splunk MCP Server auth:** `tools/call` requires a token whose `aud` claim is `mcp`; a plain
  session key is rejected. We reverse-engineered the app and mint the right token via its own
  endpoint.
- **Field extraction:** a `WinEventLog:*` *source* silently disables key=value auto-extraction —
  diagnosed and fixed with neutral source names.
- **Keeping it honest:** the agent that's *so* thorough it forgets to conclude — solved with a
  forced findings-finalization turn, then gated by the validator.

## Accomplishments

- A working, **live** agentic Splunk integration (the #1 thing most entries fail).
- A genuinely **novel, cross-track** contribution: an auditable anti-hallucination trust layer
  for agentic Splunk — useful for Security *and* as a reusable Platform/Dev-Ex harness.
- **Universal** detection + reporting: no answer keys, MITRE-mapped, multi-cloud.

## What we learned

Trust is the product. An agent that's right 95% of the time is unusable in a SOC if you can't
tell *which* 95% — so we made every claim checkable by code and every report traceable to SPL.

## What's next

- Wire the `saia_*` NL→SPL tools (Splunk AI Assistant for SPL) when cloud entitlement allows.
- Notable-event / alert-action output so confirmed findings flow back into Splunk ES.
- A baseline/anomaly layer (peer-group + time-series) on top of the behavioural detectors.

## Built with

Python (stdlib) · Splunk Enterprise 10.4 · **Splunk MCP Server (app 7931)** · Model Context
Protocol · Claude (Anthropic) · MITRE ATT&CK · graphviz.

## Links

- **Repo:** https://github.com/3sk1nt4n/SOC-Sentinel-Splunk
- **Architecture diagram:** `docs/architecture.png`
- **Sample incident report:** `reports/incident_report.html`
- **Live agent transcript:** `artifacts/sample_investigation.txt`
- **Demo video:** _(add link)_

## Compliance checklist

- ✅ Splunk AI used **at runtime** — live Splunk MCP Server tool calls (not mocked/planned)
- ✅ Architecture diagram included (`docs/architecture.png`)
- ✅ New project — all commits during the hackathon window
- ✅ OSI license — MIT (`LICENSE`, detectable in repo About)
- ✅ Public, reachable repo
