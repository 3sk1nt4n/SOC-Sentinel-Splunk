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

## Measured cost (a real run)

The agent tracks token usage and prints the `$` cost at the end of **every** run. A
**real, measured** investigation on the demo (`index=soc_demo`, full attack-chain sweep, Haiku):

```
💰 claude-haiku-4-5: 9 calls · in 2,981 + cache_read 128,293 (76% cached) + out 5,040 tok · $0.0886
```

**≈ 9 cents for a full investigation** — 24 MCP tool calls, 382 evidence rows, **7 confirmed
findings + 1 demoted by the validator**. **76% of input tokens were served from the prompt
cache** — without it the input would have been ~131k full-price tokens instead of ~3k + cached.

| Same run | Input | Output | Cost |
|---|---|---|---|
| **With caching (measured)** | 2,981 full + 128,293 cache-read | 5,040 | **$0.0886** |
| Without caching (those tokens at full price) | ~131,000 full | 5,040 | ~$0.16 |

→ caching nearly **halved** this run, and the saving grows with longer investigations
(the re-sent conversation prefix dominates the cost). The deterministic `--hunt` covers the
same 42 detectors for **$0**.

## Further opportunities (not yet enabled)

- **Cross-run prompt cache:** Anthropic's cache has a ~5-min TTL; back-to-back
  investigations in a SOC shift would re-hit the warm system/tools prefix.
- **Splunk search-result reuse:** Splunk caches dispatched search artifacts; pointing
  repeated detectors at saved searches / accelerated data models reduces Splunk load.
- **Model tiering:** Haiku for triage (default), escalate to a larger model only for the
  few findings that need deeper reasoning (`SOC_MODEL` override).
