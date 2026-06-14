# SOC Sentinel — Pipeline

`agent.py` is the conductor: deterministic Python owns every step, and the AI
(Claude) acts **only inside the `⟦ AI ✦ ⟧` brackets**. Everything that decides what
reaches you — token minting, the 3-layer validator, risk ranking, the report — is
plain code. The AI investigates and drafts; it never marks its own homework.

```
        ╔═══════════════════════════════════════════════════════════════════╗
        ║   CONDUCTOR · agent.py · deterministic Python                     ║
        ║   owns every step — the AI acts only inside the ⟦ AI ✦ ⟧ brackets ║
        ╚═══════════════════════════════════════════════════════════════════╝

 Step  0 ─▶ SETUP — point at Splunk, resolve the key   (config.py · api_key.py)
            │      .env: SPLUNK_HOST / USER / PASSWORD
            │      API key resolves env → .env → API_KEY.txt → hidden prompt
            │      (never echoed to screen · never written to git)
            │      model locked to Haiku — cost-safe (SOC_MODEL overrides)
            │
 Step  1 ─▶ CONNECT — Splunk MCP Server handshake       (splunk_mcp.py)
            │      mint an aud=mcp token  ⇄  POST /services/mcp_token
            │      MCP initialize · tools/list → 10 typed Splunk tools
            │      (splunk_run_query, get_indexes, get_metadata, …) — NEVER a shell
            │
 Step  2 ─▶ ANALYST ASK — "Investigate suspicious activity in index=…"
            │
 Step  3 ─▶ ⟦ AI ✦ INVESTIGATION LOOP — ReAct ⟧
            │   ╔═ reason ▸ act ▸ observe ════════════════════════════════╗
            │   ║  Claude forms a hypothesis, picks SPL, calls            ║
            │   ║  splunk_run_query through the MCP Server, reads the      ║
            │   ║  result rows, and refines — up to N steps               ║
            │   ╚══════════════════════════════════════════════════════════╝
            │      every result row accumulated + tagged by sourcetype
            │      (the evidence the validator will check against)
            │
 Step  4 ─▶ ⟦ AI ✦ FINALIZE ⟧ — draft findings (forced, tool-free turn)
            │      JSON per finding: { title · MITRE technique · tactic ·
            │      claims:[ field = value ] }  — concise, ≤ 8 findings
            │
 Step  5 ─▶ 🧪 3-LAYER VALIDATOR — code checks the AI   (finding_validator.py)
            │   ╔═ ⭐ THE DIFFERENTIATOR ═══════════════════════════════════╗
            │   ║  L1 TRACE        every claim → a REAL Splunk result row    ║
            │   ║  L2 CORROBORATE  count distinct independent sourcetypes    ║
            │   ║  L3 CALIBRATE    3+ sources = HIGH · 2 = MEDIUM · 1 = LOW   ║
            │   ╚════════════════════════════════════════════════════════════╝
            │      disposition: confirmed ▸ needs-review ▸ rejected ▸ inconclusive
            │      an unsupported claim is BLOCKED — never reported as fact
            │      (surfaced in the report's "Blocked by the validator" section)
            │
 Step  6 ─▶ RISK RANKING (deterministic)                (report.py)
            │      risk = confidence base × corroboration × tactic impact → 0–100
            │      findings sorted highest-risk-first
            │
 Step  7 ─▶ 📋 REPORT — risk-ranked, MITRE-mapped       (report.py → Markdown + HTML)
            │      executive summary · ATT&CK coverage matrix ·
            │      findings table (worst-first, with confidence + corroboration) ·
            │      per-technique remediation + the RE-RUNNABLE SPL that proves it ·
            │      "Blocked by the validator" · trace every claim to its search

   ════════════ alternate entry — deterministic hunt (no API key) ════════════

 --hunt ─▶ 31 UNIVERSAL BEHAVIOURAL DETECTORS · 7 domains   (detections.py)
            │      identity · endpoint · network · AWS · Azure · GCP
            │      finds BEHAVIOUR/structure, never a hardcoded IOC
            │      (no answer keys — enforced by tests/test_detections.py)
            │      each hit ─▶ 🧪 the same 3-LAYER VALIDATOR ─▶ 📋 the same REPORT
```

## Trust boundary

Splunk is read **via search only** — no destructive operations, no shell. The AI's
sole channel is the typed **Splunk MCP Server**. The **validator is the gate**: a
finding the model asserts but the data cannot support never reaches the report as
confirmed.

## Where the AI is (and is not)

The AI is invoked **only** in Steps 3 and 4 (investigate + draft). Steps 0, 1, 5, 6, 7
— connection, token minting, validation, risk ranking, and the report — are 100%
deterministic Python. That is what makes the output auditable: *the AI does the
thinking; the code checks the facts.*

**Cost:** Steps 3–4 use **Anthropic prompt caching** (the system prompt + tool
definitions + the growing conversation prefix are read at 10%) and **tool-result
memoization**, so a full investigation costs only pennies; the `--hunt` path (same 42
detectors, no LLM) is **$0**. See [`COST.md`](COST.md).
