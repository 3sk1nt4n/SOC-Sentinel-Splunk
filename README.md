# 🛡️ SOC Sentinel — the hallucination-proof investigation agent for Splunk

**Track: Security** · Splunk Agentic Ops Hackathon 2026

> AI agents over SIEM data confidently **hallucinate** — they narrate a plausible
> incident that the data doesn't support. SOC Sentinel makes that impossible to ship:
> **code, not the model, decides what's "confirmed,"** and **every finding traces back
> to the exact Splunk search result that proves it.**

## What it does
An autonomous SOC investigation agent. It reasons over your Splunk data with Claude,
runs SPL searches through the **Splunk MCP Server**, drafts findings, and then runs a
**deterministic validator**: any claim a finding makes that isn't present in the actual
Splunk result rows is flagged **UNSUPPORTED** and never reported as confirmed. The
output is an analyst-ready report where every claim is checkable in seconds.

It's a port of a battle-tested DFIR agent's anti-hallucination core (deterministic
validator + audit trail) onto Splunk data.

## How AI is used
- **Reasoning:** Claude (Anthropic) drives the loop — hypothesis → which SPL to run → read results → propose findings.
- **Splunk AI capability:** the **Splunk MCP Server** is the runtime bridge between the agent and Splunk data.
- **The guardrail:** a deterministic validator (`src/finding_validator.py`) gates every finding against the real search rows.

See [`architecture_diagram.md`](architecture_diagram.md).

## Setup
**Prerequisites:** Splunk Enterprise (free trial + Developer License) running locally, and the **Splunk MCP Server** pointed at it.

1. **Splunk:** install Splunk Enterprise, start it (`/opt/splunk/bin/splunk start`), apply a Developer License. Mgmt API at `https://localhost:8089`.
2. **Splunk MCP Server:** install from the hackathon Resources page; point it at `https://localhost:8089`.
3. **Config:** `cp .env.example .env` and fill in your Splunk host/user/password + the MCP Server endpoint.
4. **Python deps:** standard library only for the Splunk client + validator (no pip needed); the agent loop uses the `anthropic` SDK (`pip install anthropic`) and your `ANTHROPIC_API_KEY`.

## Run
```bash
# 1. sanity: query Splunk directly (proves connectivity)
python3 src/splunk_client.py 'index=_internal | head 5'

# 2. validate a finding against live Splunk results (the differentiator)
python3 -c "import sys;sys.path.insert(0,'src');from splunk_client import run_spl;from finding_validator import validate_finding;\
r=run_spl('index=_internal | head 20');print(validate_finding({'id':'F1','title':'demo','claims':[{'field':'host','value':r[0]['host']}]}, r)['disposition'])"
```
*(The full agent loop — Claude orchestration over the MCP Server — is `src/soc_sentinel.py`; see the demo video.)*

## Why it matters
For a SOC, a confident wrong answer is worse than no answer. SOC Sentinel's validator
turns the agent from a plausible-story generator into one whose every "confirmed"
finding is backed by a Splunk result an analyst can re-run.

## License
MIT — see [LICENSE](LICENSE).
