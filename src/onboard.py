#!/usr/bin/env python3
"""SOC Sentinel — one-command onboarding.

A fancy, colorful walkthrough (in the spirit of Find Evil's ./findevil.sh):
  glowy banner -> environment health cards -> hidden API-key paste with LIVE
  verification -> pick a mode -> run. No flags to remember; just `./soc-sentinel.sh`.
"""
from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

R = "\x1b[0m"; B = "\x1b[1m"; DIM = "\x1b[2m"
GRN = "\x1b[38;5;71m"; RED = "\x1b[38;5;174m"; YEL = "\x1b[38;5;179m"
BLU = "\x1b[38;5;75m"; CYN = "\x1b[38;5;80m"; MAG = "\x1b[38;5;141m"; GRY = "\x1b[38;5;245m"
TTY = sys.stdin.isatty() and sys.stdout.isatty()


def banner():
    try:   # --static: one clean frame (random colour scheme), never floods the scrollback
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "intro.py"), "--static"], timeout=20)
    except Exception:
        print(f"\n{B}{CYN}SOC SENTINEL{R} — agentic SOC analyst you can trust\n")


def section(title):
    print(f"\n{B}{BLU}── {title} {'─' * max(0, 56 - len(title))}{R}")


def card(status, label, detail=""):
    icon = {"ok": f"{GRN}✓{R}", "no": f"{RED}✗{R}", "warn": f"{YEL}●{R}", "info": f"{CYN}•{R}"}[status]
    print(f"   {icon} {B}{label}{R}{('  ' + DIM + detail + R) if detail else ''}")


def ask(prompt, default=""):
    if not TTY:
        return default
    try:
        a = input(f"   {MAG}?{R} {prompt} ").strip()
        return a or default
    except (EOFError, KeyboardInterrupt):
        return default


# ---------------------------------------------------------------- key
def _looks_real(k):
    return isinstance(k, str) and k.strip().startswith("sk-ant-") and "..." not in k and len(k.strip()) > 24


def _validate_key(key):
    """One-token live call so we never start a run with a dead key (live verification)."""
    body = json.dumps({"model": "claude-haiku-4-5-20251001", "max_tokens": 1,
                       "messages": [{"role": "user", "content": "hi"}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST")
    req.add_header("x-api-key", key.strip())
    req.add_header("anthropic-version", "2023-06-01")
    req.add_header("content-type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=30)
        return True
    except urllib.error.HTTPError as e:
        return False if e.code in (401, 403) else None
    except Exception:
        return None


def _candidate_keys():
    """Yield (source, key) from env -> .env -> API_KEY.txt (deduped), so a valid key in
    any source is used even if an earlier (e.g. expired env-var) key shadows it."""
    seen = set()
    k = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if k and k not in seen:
        seen.add(k); yield ("env var", k)
    try:
        from config import load_env
        k = (load_env().get("ANTHROPIC_API_KEY") or "").strip()
        if k and k not in seen:
            seen.add(k); yield (".env", k)
    except Exception:
        pass
    p = os.path.join(ROOT, "API_KEY.txt")
    if os.path.isfile(p):
        for ln in reversed(open(p, encoding="utf-8").read().splitlines()):
            ln = ln.strip()
            if ln.startswith("sk-") and ln not in seen:
                seen.add(ln); yield ("API_KEY.txt", ln); break


def handle_key():
    """Try every key source, LIVE-verify each, use the first that works; only prompt if none do."""
    for ksrc, k in _candidate_keys():
        v = _validate_key(k)
        if v is True:
            card("ok", "API key", f"loaded from {ksrc} (…{k[-4:]}) — verified live")
            return k
        if v is None:
            card("warn", "API key", f"loaded from {ksrc} (…{k[-4:]}) — couldn't reach Anthropic; using it")
            return k
        # rejected -> quietly try the next source
    if not TTY:
        card("info", "API key", "none working — running the free hunt")
        return None
    card("info", "API key", "no working key found — paste one (Enter = skip to the free $0 hunt)")
    print(f"   {DIM}easiest: put it in API_KEY.txt and re-run — then you're never asked.{R}")
    for attempt in range(4):
        k = getpass.getpass(f"   {MAG}🔑{R} paste your Anthropic key (hidden): ").strip().strip("'\"")
        if not k:
            card("info", "skipped", "the free 42-detector hunt finds everything too")
            return None
        if not (k.startswith("sk-") or len(k) >= 40):     # lenient — the live call is the real test
            print(f"   {YEL}that doesn't look like a key.{R} {DIM}paste sk-ant-…, or Enter to skip.{R}")
            if attempt >= 1:
                print(f"   {DIM}tip: many terminals won't paste into a hidden prompt — instead run, in another shell:")
                print(f"        printf 'sk-ant-YOURKEY\\n' > API_KEY.txt   then ./soc-sentinel.sh again.{R}")
            continue
        v = _validate_key(k)
        if v is True:
            card("ok", "API key", "verified live ✓")
            if ask("save it to API_KEY.txt for next time? [Y/n]", "y").lower().startswith("y"):
                try:
                    open(os.path.join(ROOT, "API_KEY.txt"), "w").write(k + "\n")
                    card("ok", "saved", "API_KEY.txt (gitignored)")
                except OSError:
                    pass
            return k
        if v is None:
            card("warn", "API key", "couldn't reach Anthropic — using it anyway")
            return k
        print(f"   {RED}Anthropic rejected that key (expired/typo?).{R} {DIM}try again or Enter to skip.{R}")
    card("info", "continuing", "no key — running the free 42-detector hunt")
    return None


# ---------------------------------------------------------------- env
def check_env():
    section("Checking your Splunk")
    from splunk_mcp import SplunkMCP, SplunkMCPError
    mcp = SplunkMCP()
    try:
        info = mcp.initialize()
        tools = mcp.list_tools()
        card("ok", "Splunk MCP Server", f"{(info.get('serverInfo') or {}).get('version','?')} · {len(tools)} typed tools")
    except SplunkMCPError as e:
        card("no", "Splunk MCP Server", str(e)[:70])
        print(f"\n   {RED}Can't reach the MCP Server.{R} Check .env (SPLUNK_HOST/USER/PASSWORD) and that the\n"
              f"   Splunk MCP Server app is installed. See docs/GETTING_STARTED.md.")
        return None, 0
    try:
        n = int(mcp.run_query("search index=soc_demo earliest=-24h | stats count")[0].get("count", 0))
    except Exception:
        n = 0
    if n:
        card("ok", "Evidence", f"index=soc_demo · {n} events (last 24h)")
    else:
        card("warn", "Evidence", "index=soc_demo is empty")
        if ask("seed a reproducible demo breach now? [Y/n]", "y").lower().startswith("y"):
            subprocess.run([sys.executable, os.path.join(HERE, "seed_demo_index.py"), "--reset"])
            try:
                n = int(mcp.run_query("search index=soc_demo earliest=-24h | stats count")[0].get("count", 0))
                card("ok", "Evidence", f"index=soc_demo · {n} events seeded")
            except Exception:
                pass
    return mcp, n


# ---------------------------------------------------------------- run
def run_mode(mode, mcp, key, question):
    import agent
    if key:
        agent._RESOLVED_KEY = key            # use the verified key, bypass the dead env one
    if mode == "hunt":
        section("Universal hunt — 42 behavioural detectors (free, no LLM)")
        from detections import hunt, print_hunt
        from report import from_hunt, write_reports
        res = hunt(mcp, "soc_demo")
        print_hunt(res)
        p = write_reports(from_hunt(res, "soc_demo"), index="soc_demo", scope_label="Universal hunt")
        card("ok", "Report", f"{p['html']}")
    elif mode == "demo":
        section("Trust-gate demo (free, no LLM)")
        agent.demo_validator_gate()
    else:
        section("Live investigation — Claude over the Splunk MCP Server")
        from report import from_agent, write_reports
        res = agent.run_investigation(question)
        agent._print_report(res)
        p = write_reports(from_agent(res, "soc_demo"), index="soc_demo", scope_label="Claude investigation")
        c = (res.get("usage") or {}).get("cost_usd")
        card("ok", "Report", f"{p['html']}")
        if c is not None:
            card("ok", "Cost", f"this investigation: ${c:.4f}")


def main():
    banner()
    mcp, n = check_env()
    if mcp is None:
        sys.exit(1)
    section("Your AI key")
    key = handle_key()

    section("What would you like to do?")
    default = "1" if key else "2"
    print(f"   {B}1{R}  Investigate with AI   {DIM}(Claude finds the attack · ~pennies on Haiku){R}")
    print(f"   {B}2{R}  Run the detector hunt {DIM}(42 detectors · free, no key){R}")
    print(f"   {B}3{R}  Trust-gate demo       {DIM}(see the validator block a hallucination · free){R}")
    choice = ask(f"choose [1/2/3] (Enter = {default}):", default)
    mode = {"1": "agent", "2": "hunt", "3": "demo"}.get(choice, "agent" if key else "hunt")
    if mode == "agent" and not key:
        card("warn", "no key", "falling back to the free detector hunt")
        mode = "hunt"

    q = ("Was anything compromised in index=soc_demo in the last 24h? Find the attacker, the "
         "compromised account, lateral movement, persistence and exfiltration.")
    if mode == "agent" and TTY:
        print(f"   {DIM}e.g.  \"find brute force then lateral movement\"  ·  "
              f"\"any data exfiltration or anti-forensics?\"  ·  \"is account X compromised?\"{R}")
        qi = ask("describe what to investigate (or press Enter for a full attack-chain sweep):", "")
        if len(qi.strip()) < 10:                 # guardrail: don't run on junk/typos like "k"
            if qi.strip():
                card("info", "too short", "running the full attack-chain sweep instead")
            # q stays the default
        else:
            q = qi

    run_mode(mode, mcp, key, q)
    print(f"\n   {GRN}{B}✓ Done.{R} {DIM}Open reports/incident_report.html for the full risk-ranked report.{R}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{DIM}cancelled.{R}")
