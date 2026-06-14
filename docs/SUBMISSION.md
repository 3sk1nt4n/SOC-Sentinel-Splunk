# Devpost submission — copy-paste sheet

Paste each block into the matching Devpost field. Track = **Security**.

---

## Project name
```
SOC Sentinel
```

## Elevator pitch / tagline
```
An agentic SOC analyst for Splunk you can trust — Claude investigates your data through the Splunk MCP Server, and code (not the model) verifies every finding against real results before it's reported.
```

## "Built with" (tags)
```
python, splunk, splunk-mcp-server, model-context-protocol, anthropic, claude, mitre-attack, security, soc, ai-agent
```

## "Try it out" links
```
GitHub: https://github.com/3sk1nt4n/SOC-Sentinel-Splunk
```
*(also add your demo-video link once uploaded)*

---

## About the project  (paste into the description / story box)

### The problem
Point an AI at your SIEM and ask *"was I breached?"* and it will confidently **invent** an attacker IP, a hostname, a whole "confirmed" breach that isn't in your data. In security a confident wrong answer is worse than no answer — wasted IR hours, wrong escalations, real threats missed. It's the #1 reason agentic SOC tooling isn't trusted in production.

### What it does
SOC Sentinel is an autonomous SOC analyst for Splunk. You ask a plain-English question; **Claude** investigates your Splunk data **through the Splunk MCP Server**, then a deterministic **3-layer validator** checks every claim against real Splunk result rows — anything it can't prove is **blocked** before it reaches you. You get a risk-ranked, MITRE-mapped report where every finding traces back to a re-runnable SPL search.

### How AI + Splunk are used (at runtime — not mocked)
- **Splunk AI capability:** the **Splunk MCP Server** (Splunkbase app 7931, Splunk-supported) is the agent's only channel to Splunk — live `splunk_run_query` and friends over JSON-RPC at `/services/mcp`. Verified live: **24 MCP tool calls, 382 result rows, $0.0886 per investigation** (76% prompt-cache hit) on Claude Haiku.
- **Reasoning:** Claude forms a hypothesis, picks which SPL to run, reads the rows, proposes findings.
- **The guardrail (the differentiator):** a 3-layer validator — **L1 trace** (every claim → a real row), **L2 corroboration** (independent sourcetypes), **L3 calibration** (3+ sources = HIGH) — gates every finding. *Code, not the model, decides what's confirmed.*

### How we built it
- `splunk_mcp.py` — a stdlib MCP client: mints an `aud=mcp` token, speaks MCP Streamable-HTTP JSON-RPC.
- `finding_validator.py` — the 3-layer trust pipeline.
- `detections.py` — **42 universal behavioural detectors** across identity, endpoint, network, AWS, Azure, GCP — including the log-native equivalents of Volatility `malfind`/`hollowprocess` (CreateRemoteThread, ProcessTampering, reflective DLL) — **no hardcoded IOCs** (a test enforces it).
- `agent.py` — the Claude tool-use loop with **prompt caching + tool-result memoization** (a full run = ~9¢, 76% cached).
- `report.py` — risk-ranked Markdown + HTML reports with remediation and the re-runnable SPL.
- `seed_demo_index.py` — a reproducible 6-sourcetype ATT&CK breach so judges can run the whole thing in two minutes.
- `./soc-sentinel.sh` — a one-command guided onboarding.

### Challenges
Reverse-engineering the MCP Server's `aud=mcp` token auth; a `WinEventLog:*` source silently disabling field extraction; keeping the agent honest (forced findings-finalization, then the validator).

### Accomplishments
A **live** agentic Splunk integration (most entries fail this), a novel and cross-track **auditable anti-hallucination trust layer**, and a universal, multi-cloud, MITRE-mapped detection library — all reproducible and case-neutral.

### What's next
Wire the `saia_*` NL→SPL tools; push confirmed findings back into Splunk ES as notable events; a baseline/anomaly layer on top of the behavioural detectors.

### Built with
Python (stdlib) · Splunk Enterprise 10.4 · Splunk MCP Server (app 7931) · Model Context Protocol · Claude (Anthropic) · MITRE ATT&CK · graphviz.

---

## Compliance (paste nowhere — just confirm before submitting)
- ✅ Splunk AI used at runtime (live MCP Server tool calls)
- ✅ Architecture diagram (`docs/architecture.png`)
- ✅ New project, hackathon window
- ✅ OSI license (MIT, in repo About)
- ✅ Public, reachable repo
