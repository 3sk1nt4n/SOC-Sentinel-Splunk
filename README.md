# 🛡️ SOC Sentinel — the hallucination-proof investigation agent for Splunk

**Track: Security** · Splunk Agentic Ops Hackathon 2026 · uses the **Splunk MCP Server** at runtime

> An autonomous SOC analyst that investigates your Splunk data with Claude — but
> where **code, not the model, decides what's "confirmed."** Every finding traces
> back to the exact Splunk search result that proves it; anything the AI can't
> prove is **blocked before it ever reaches the report.**

![SOC Sentinel architecture](docs/architecture.png)

---

## The problem

Point an LLM at your SIEM and ask *"was I breached?"* and it will happily **invent**
an attacker IP, a hostname, a "confirmed" lateral-movement chain — none of it in your
data. In security that isn't a quirk, it's a dealbreaker: **a confident wrong answer is
more dangerous than no answer** — wasted incident-response hours, wrong escalations,
real threats missed while chasing a fabricated one. It is the single biggest reason
agentic SOC tooling isn't trusted in production.

## What it solves

| Issue with naïve "AI over SIEM" | How SOC Sentinel addresses it |
|---|---|
| **Hallucinated facts** — invented IPs, hosts, "confirmed" breaches | **Layer 1 trace gate** — every claim must match a real Splunk result row or it's blocked. Code decides, not the model. |
| **No provenance** — you can't verify what the AI claims | every confirmed finding links to the exact **SPL + rows** that prove it — re-runnable in seconds |
| **Mis-calibrated confidence** | **Layer 3 calibration** — confidence from *independent-source corroboration* (3+ sourcetypes = HIGH), not the model's gut feel |
| **Unsafe access / prompt injection** | the agent never builds raw queries or shell — only **typed MCP tools, read-only search** |
| **Alert fatigue** | verifiable triage ranked by corroboration, so analysts see what's *real* first |
| **Trust gap blocks adoption** | the report contains nothing unverifiable — safe to hand straight to a SOC |

---

## How it works (the 3-layer trust pipeline)

The anti-hallucination core is ported from a battle-tested DFIR agent and reimplemented
for Splunk. Every candidate finding the AI proposes runs through three deterministic layers:

1. **Layer 1 — Trace gate.** Each claim (`field = value`) must appear in a real Splunk
   result row, or it is `UNSUPPORTED` and blocked. *Code checks the AI.*
2. **Layer 2 — Corroboration.** Count the **independent sourcetypes** that back the
   finding (the Splunk analog of memory + disk + logs cross-checking).
3. **Layer 3 — Calibration.** Evidence-based confidence: **3+ independent sources = HIGH,
   2 = MEDIUM, 1 = LOW.**

Disposition: `confirmed` (all claims trace) · `needs_review` (some) · `rejected` (none) ·
`inconclusive` (no claims). Confidence is only ever assigned to confirmed findings.

## How AI + Splunk are used (at runtime)

- **Reasoning:** **Claude (Anthropic)** drives the investigation loop — forms a hypothesis,
  picks which SPL to run, reads results, proposes findings with explicit claims.
- **Splunk AI capability:** the **Splunk MCP Server** (Splunkbase app 7931, Splunk-supported)
  is the runtime bridge — the agent issues `splunk_run_query` and the other typed MCP tools
  over JSON-RPC at `POST /services/mcp`; it never touches Splunk directly.
- **The guardrail:** the 3-layer validator (`src/finding_validator.py`) gates every finding
  against the real rows.

See [`architecture_diagram.md`](architecture_diagram.md) for the full data flow.

---

## Quickstart

**Prerequisites:** Splunk Enterprise running locally (mgmt API at `https://localhost:8089`)
with the **Splunk MCP Server** app installed, and Python 3 (the client/validator are
**stdlib-only** — no pip needed; the agent loop calls the Anthropic API over stdlib too).

```bash
cp .env.example .env          # set SPLUNK_HOST / SPLUNK_USER / SPLUNK_PASSWORD

# 1. prove the MCP integration (lists the 10 tools, runs a real search)
python3 src/splunk_mcp.py

# 2. seed a reproducible breach into Splunk (index=soc_demo) — no BOTS download
python3 src/seed_demo_index.py

# 3. THE DIFFERENTIATOR — 3-layer gate on real security data, no API key needed
python3 src/agent.py --demo

# 4. full agentic loop (Claude drives it) — add a key any of 4 ways, then:
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env      # or env var / API_KEY.txt / hidden prompt
python3 src/agent.py "Investigate suspicious authentication and outbound activity in index=soc_demo over the last 24h."
```

### What step 3 prints (live, deterministic, no LLM)

```
✅ CONFIRMED  [MEDIUM]  External 203.0.113.66 ran a brute-force + web attack
     L1 trace gate:    1/1 claims trace to real Splunk rows
     L2 corroboration: 2 independent source(s): access_combined, linux_secure
     L3 calibration:   confidence=MEDIUM  (3+ sources=HIGH, 2=MEDIUM, 1=LOW)

🚫 REJECTED  [NONE]  C2 beacon to 8.8.8.8 (model-invented)
     L1 trace gate:    0/1 claims trace to real Splunk rows
```

The invented beacon can't reach "confirmed" — its `dest_ip` never appears in a Splunk row.
That gate is what stops AI hallucinations reaching the report.

---

## Layout

| File | Purpose |
|---|---|
| `src/splunk_mcp.py` | Splunk MCP Server client — token mint + JSON-RPC (`initialize`/`tools/list`/`tools/call`) |
| `src/agent.py` | the agentic loop (Claude over MCP) + the deterministic gate demo |
| `src/finding_validator.py` | the 3-layer trust pipeline — **the differentiator** |
| `src/seed_demo_index.py` | reproducible SOC dataset (a full intrusion to hunt) |
| `src/api_key.py` | "can't-get-stuck" key entry: env → .env → `API_KEY.txt` → hidden prompt |
| `tests/test_validator.py` | unit tests for the 3 layers |
| `docs/architecture.png` | the architecture diagram (above) |

## Compliance (anti-disqualification)

- ✅ **Splunk AI used at runtime** — the agent calls the Splunk MCP Server live (not mocked / not planned)
- ✅ **Architecture diagram** — `docs/architecture.png`
- ✅ **New project** — all commits during the hackathon period
- ✅ **OSI license** — MIT ([LICENSE](LICENSE))
- ✅ **Public repo** — see About

## License
MIT — see [LICENSE](LICENSE).
