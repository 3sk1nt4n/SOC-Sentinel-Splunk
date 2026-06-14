# Cost & caching

## What costs money (and what doesn't)

| Mode | What runs | LLM cost |
|---|---|---|
| `--demo` (the gate proof) | deterministic validator on real Splunk rows | **$0** (no LLM) |
| `--hunt` (42-detector pack) | deterministic SPL + the 3-layer validator | **$0** (no LLM) |
| live agent (`run_investigation`) | Claude drives the MCP tools + the validator | a few **cents** per investigation (Haiku) |

The Splunk side is free (it's your Splunk); searches are **read-only oneshot** queries.
Only the *live agent* spends on the Anthropic API — and it's locked to **Haiku** for cost.

## Where the agent's tokens go

The agent is a tool-use loop: each step re-sends the **system prompt + tool definitions +
the whole conversation so far** (which grows as tool results pile up). Over ~10–12 steps
that re-sent prefix is the dominant cost — it's *mostly the same bytes every step*. That
is exactly what caching removes.

## Caching — implemented

**1 · Prompt caching (Anthropic `cache_control: ephemeral`)** — `src/agent.py`:
- the **system prompt** and the **tool definitions** (static, re-sent every step) are cached;
- the **growing conversation prefix** gets a moving cache breakpoint each turn, so every
  step re-reads the prior turns at **10% of input price** instead of full price.

**2 · Tool-result memoization** — identical `splunk_run_query` calls within one
investigation are served from an in-run cache (no duplicate Splunk searches).

Cached input is billed at **10%** (read) / writes at **125%** of input price, so once the
prefix is warm the per-step cost collapses to *only the newest turn at full price*.

## Real measurement (built in)

The agent now tracks usage and prints, at the end of every run:

```
💰 claude-haiku-4-5: 12 calls · in 14,200 + cache_read 168,400 (92% cached) + out 9,100 tok · $0.0731
```

Run any live investigation to get exact numbers for your data. *(At the time of writing
the live figure could not be captured here because the available API key returned 401 —
the instrumentation is in place and prints automatically once a valid key is used.)*

## Estimated cost per investigation (Haiku · $1 in / $5 out / $0.10 cache-read per MTok)

Grounded in earlier real runs (≈ 26–43 MCP tool calls, 230–410 evidence rows, ~10–12 steps):

| | Cumulative input | Output | Estimated cost |
|---|---|---|---|
| **Without caching** | ~150k–300k tok (prefix re-sent each step) | ~8k–15k tok | **~$0.15 – $0.30** |
| **With caching** (≈ 80–90% of input read from cache) | ~30k full + ~170k cache-read | ~8k–15k tok | **~$0.05 – $0.10** |

→ roughly a **2–4× reduction**, putting a full investigation at **pennies**. The
deterministic `--hunt` covers the same 42 detectors for **$0**.

## Further opportunities (not yet enabled)

- **Cross-run prompt cache:** Anthropic's cache has a ~5-min TTL; back-to-back
  investigations in a SOC shift would re-hit the warm system/tools prefix.
- **Splunk search-result reuse:** Splunk caches dispatched search artifacts; pointing
  repeated detectors at saved searches / accelerated data models reduces Splunk load.
- **Model tiering:** Haiku for triage (default), escalate to a larger model only for the
  few findings that need deeper reasoning (`SOC_MODEL` override).
