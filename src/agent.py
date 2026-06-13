"""SOC Sentinel — the agentic investigation loop.

An LLM agent (Claude) investigates a security question by calling Splunk **at
runtime through the official Splunk MCP Server** (a Splunk AI capability), then a
deterministic validator gates every finding: a claim is reported as fact only if
it traces to a real row in the Splunk results that produced it. Code checks the
model — that is the whole point.

Two entry points:
  * run_investigation(question)  — full agentic loop (needs ANTHROPIC_API_KEY +
                                    network); Claude drives the Splunk MCP tools.
  * demo_validator_gate()        — deterministic proof of the anti-hallucination
                                    gate using REAL Splunk data and NO LLM, so the
                                    differentiator is verifiable without a key.

stdlib only. The Anthropic Messages API is called over urllib (tool-use loop)."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_env  # noqa: E402
from finding_validator import validate_finding  # noqa: E402
from splunk_mcp import SplunkMCP, SplunkMCPError  # noqa: E402

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = os.environ.get("SOC_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are SOC Sentinel, an autonomous security analyst working \
inside Splunk. Investigate the analyst's question using ONLY the Splunk tools \
provided (they reach Splunk through the Splunk MCP Server). Form a hypothesis, \
run searches to gather evidence, and refine.

Discipline:
- Never assert anything you did not observe in tool output. No guessing.
- Prefer specific SPL that returns the concrete values you will cite.
- When done, output a SINGLE fenced ```json block, no prose after it, shaped:
  {"findings": [
     {"id": "F1", "title": "...", "severity": "high|medium|low",
      "summary": "...",
      "claims": [{"field": "<result field>", "value": "<exact value seen>"}]}
  ]}
  Every claim's field/value MUST be a column/value you actually saw in a result \
row. The host system will independently re-check each claim against the Splunk \
rows; unsupported claims are dropped, so do not pad."""


# --------------------------------------------------------------------------
# Anthropic Messages API (tool-use loop)
# --------------------------------------------------------------------------
def _api_key() -> str:
    cfg = load_env()
    key = os.environ.get("ANTHROPIC_API_KEY") or cfg.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set (env or .env). Needed for the live agent loop.")
    return key


def _anthropic(messages, tools, *, model, max_tokens=2048):
    body = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "system": SYSTEM_PROMPT, "messages": messages, "tools": tools,
    }).encode()
    req = urllib.request.Request(ANTHROPIC_URL, data=body, method="POST")
    req.add_header("x-api-key", _api_key())
    req.add_header("anthropic-version", "2023-06-01")
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Anthropic API HTTP {e.code}: {e.read().decode()[:400]}")


def tool_specs_from_mcp(mcp: SplunkMCP) -> list[dict]:
    """Expose the live Splunk MCP tools to Claude in Anthropic tool-schema form."""
    specs = []
    for t in mcp.list_tools():
        specs.append({
            "name": t["name"],
            "description": (t.get("description") or "")[:1024],
            "input_schema": t.get("inputSchema") or {"type": "object", "properties": {}},
        })
    return specs


def _extract_findings(text: str) -> list[dict]:
    """Pull the findings list out of the model's final ```json block."""
    if "```" in text:
        seg = text.split("```", 2)
        block = seg[1] if len(seg) > 1 else text
        block = block[4:] if block.lstrip().lower().startswith("json") else block
        block = block.strip().lstrip("json").strip()
    else:
        block = text
    try:
        data = json.loads(block)
        return data.get("findings", []) if isinstance(data, dict) else []
    except Exception:
        return []


# --------------------------------------------------------------------------
# The agentic investigation
# --------------------------------------------------------------------------
def run_investigation(question: str, *, model: str = DEFAULT_MODEL,
                      max_steps: int = 10, verbose: bool = True) -> dict:
    mcp = SplunkMCP()
    mcp.initialize()
    tools = tool_specs_from_mcp(mcp)

    messages = [{"role": "user", "content": question}]
    evidence_rows: list[dict] = []     # union of every result row Splunk returned
    audit: list[dict] = []             # every tool call (for the trace)
    final_text = ""

    for step in range(max_steps):
        resp = _anthropic(messages, tools, model=model)
        blocks = resp.get("content", [])
        messages.append({"role": "assistant", "content": blocks})

        tool_uses = [b for b in blocks if b.get("type") == "tool_use"]
        for b in blocks:
            if b.get("type") == "text" and b.get("text", "").strip():
                final_text = b["text"]
                if verbose:
                    print(f"\n🧠 [{step}] {b['text'][:600]}")

        if resp.get("stop_reason") != "tool_use" or not tool_uses:
            break

        tool_results = []
        for tu in tool_uses:
            name, args = tu["name"], tu.get("input", {})
            if verbose:
                print(f"🔧 MCP call: {name}({json.dumps(args)[:160]})")
            try:
                out = mcp.call_tool(name, args)
                rows = out.get("results", []) if isinstance(out, dict) else []
                evidence_rows.extend(r for r in rows if isinstance(r, dict))
                audit.append({"tool": name, "args": args, "rows": len(rows)})
                payload = json.dumps(out)[:6000]
            except SplunkMCPError as e:
                audit.append({"tool": name, "args": args, "error": str(e)})
                payload = json.dumps({"error": str(e)})
            tool_results.append({"type": "tool_result",
                                 "tool_use_id": tu["id"], "content": payload})
        messages.append({"role": "user", "content": tool_results})

    findings = _extract_findings(final_text)
    validated = [validate_finding(f, evidence_rows) for f in findings]
    return {"question": question, "findings": validated,
            "audit": audit, "evidence_row_count": len(evidence_rows),
            "raw_findings": findings}


# --------------------------------------------------------------------------
# Deterministic proof of the gate (REAL Splunk data, NO LLM, NO key)
# --------------------------------------------------------------------------
def demo_validator_gate() -> dict:
    """Run two real Splunk MCP queries, then push one TRUE finding and one
    HALLUCINATED finding through the validator. Proves code, not the model,
    decides what is 'confirmed'. Runnable with zero network beyond localhost."""
    mcp = SplunkMCP()
    mcp.initialize()

    # Real evidence pulled live through the Splunk MCP Server.
    rows = mcp.run_query(
        "search index=_internal | head 200 | stats count by sourcetype | sort -count | head 8")
    print(f"\n📡 Splunk MCP Server returned {len(rows)} real rows. Sample:")
    for r in rows[:3]:
        print("   ", r)
    if not rows:
        print("   (no rows — is index=_internal populated?)")
        return {}

    top = rows[0]                       # a value we genuinely observed
    true_finding = {
        "id": "F1", "title": "High-volume internal sourcetype observed",
        "claims": [{"field": "sourcetype", "value": top.get("sourcetype")}],
    }
    fake_finding = {
        "id": "F2", "title": "Beacon to attacker C2 (model-invented)",
        "claims": [{"field": "sourcetype", "value": "evil:attacker:c2:beacon"}],
    }

    print("\n🔒 Validator gate (code checks the claims against real Splunk rows):")
    out = []
    for f in (true_finding, fake_finding):
        v = validate_finding(f, rows)
        out.append(v)
        mark = "✅ CONFIRMED" if v["disposition"] == "confirmed" else "🚫 NOT CONFIRMED"
        print(f"  {mark}: {f['title']}")
        for line in v["trace"]:
            print(f"        {line}")
    print("\n→ The invented C2 finding cannot reach 'confirmed' — it never matched a "
          "Splunk row. That gate is what stops AI hallucinations reaching the report.")
    return {"validated": out, "evidence_rows": len(rows)}


def _print_report(result: dict) -> None:
    print("\n" + "=" * 64)
    print("SOC SENTINEL — INVESTIGATION REPORT")
    print("=" * 64)
    print("Question:", result["question"])
    print(f"Evidence rows gathered via Splunk MCP: {result['evidence_row_count']}")
    print(f"Tool calls: {len(result['audit'])}")
    confirmed = [f for f in result["findings"] if f["disposition"] == "confirmed"]
    review = [f for f in result["findings"] if f["disposition"] != "confirmed"]
    print(f"\n✅ Confirmed (every claim traced to Splunk): {len(confirmed)}")
    for f in confirmed:
        print(f"   - {f['title']}")
        for line in f["trace"]:
            print(f"        {line}")
    print(f"\n🚫 Needs review / unsupported claims dropped: {len(review)}")
    for f in review:
        print(f"   - {f['title']}")
        for line in f["trace"]:
            print(f"        {line}")


if __name__ == "__main__":
    if "--demo" in sys.argv or not (os.environ.get("ANTHROPIC_API_KEY")
                                    or load_env().get("ANTHROPIC_API_KEY")):
        print("Running deterministic validator-gate demo (no API key needed)…")
        demo_validator_gate()
    else:
        q = " ".join(a for a in sys.argv[1:] if not a.startswith("-")) or \
            "Which sourcetypes in index=_internal show errors in the last 24h?"
        _print_report(run_investigation(q))
