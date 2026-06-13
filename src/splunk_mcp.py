"""Splunk MCP Server client — SOC Sentinel's runtime channel to Splunk.

This talks to the official **Splunk MCP Server** (Splunkbase app 7931, Splunk-
supported) over its MCP Streamable-HTTP endpoint, which splunkd exposes as a
persistent REST handler at:

    POST {SPLUNK_HOST}/services/mcp        # JSON-RPC 2.0

Auth model (verified against the app source): tools/call requires a Splunk token
whose `aud` claim == "mcp". We mint exactly that with the app's own endpoint:

    GET {SPLUNK_HOST}/services/mcp_token?username=<user>   # Basic auth

which returns an RSA-encrypted bearer token we present as `Authorization: Bearer`.
The token is minted on demand from the .env credentials and cached in-process —
nothing long-lived is written to disk.

stdlib only (urllib); tolerant of Splunk's self-signed dev cert. The MCP tool
names are prefixed, e.g. `splunk_run_query`, `splunk_get_indexes`."""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_env  # noqa: E402

MCP_PROTOCOL_VERSION = "2025-06-18"


class SplunkMCPError(RuntimeError):
    """A JSON-RPC error or transport failure from the Splunk MCP Server."""


class SplunkMCP:
    """Minimal MCP client for the Splunk MCP Server (Streamable-HTTP / JSON-RPC)."""

    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_env()
        self.host = self.cfg["SPLUNK_HOST"].rstrip("/")
        self.user = self.cfg["SPLUNK_USER"]
        self._password = self.cfg["SPLUNK_PASSWORD"]
        # Allow a pre-minted token via .env (SPLUNK_MCP_TOKEN); else mint on demand.
        self._token: str | None = self.cfg.get("SPLUNK_MCP_TOKEN") or None
        self._rpc_id = 0
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # --- low-level HTTP ---------------------------------------------------
    def _basic_header(self) -> str:
        raw = f"{self.user}:{self._password}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def _send(self, method: str, path: str, *, headers=None, data=None, params=None):
        url = self.host + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=120) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    # --- auth -------------------------------------------------------------
    def mint_token(self, username: str | None = None, force: bool = False) -> str:
        """Mint (and cache) an aud=mcp bearer token via /services/mcp_token."""
        if self._token and not force:
            return self._token
        st, body = self._send(
            "GET", "/services/mcp_token",
            headers={"Authorization": self._basic_header()},
            params={"username": username or self.user, "output_mode": "json"},
        )
        if st != 200:
            raise SplunkMCPError(f"token mint failed (HTTP {st}): {body[:300]}")
        token = (json.loads(body) or {}).get("token")
        if not token:
            raise SplunkMCPError(f"token mint returned no token: {body[:300]}")
        self._token = token
        return token

    # --- JSON-RPC ---------------------------------------------------------
    def _rpc(self, rpc_method: str, params: dict | None = None,
             *, notify: bool = False) -> dict | None:
        """One JSON-RPC call to /services/mcp. Re-mints the token once on 401/403."""
        for attempt in (1, 2):
            token = self.mint_token(force=(attempt == 2))
            rpc_id = None
            if not notify:
                self._rpc_id += 1
                rpc_id = self._rpc_id
            payload = json.dumps({
                "jsonrpc": "2.0", "id": rpc_id,
                "method": rpc_method, "params": params or {},
            }).encode()
            st, body = self._send(
                "POST", "/services/mcp", data=payload,
                headers={"Authorization": "Bearer " + token,
                         "Content-Type": "application/json"},
            )
            if st in (401, 403) and attempt == 1 and not self.cfg.get("SPLUNK_MCP_TOKEN"):
                self._token = None  # stale token — re-mint and retry once
                continue
            if notify:
                return None
            if st != 200:
                raise SplunkMCPError(f"{rpc_method} failed (HTTP {st}): {body[:400]}")
            parsed = json.loads(body) if body else {}
            if isinstance(parsed, dict) and parsed.get("error"):
                raise SplunkMCPError(f"{rpc_method}: {parsed['error']}")
            return parsed
        raise SplunkMCPError(f"{rpc_method}: authentication failed after re-mint")

    # --- MCP protocol surface --------------------------------------------
    def initialize(self) -> dict:
        r = self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "soc-sentinel", "version": "0.1"},
        })
        self._rpc("notifications/initialized", notify=True)
        return (r or {}).get("result", {})

    def list_tools(self) -> list[dict]:
        r = self._rpc("tools/list")
        return (r or {}).get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call an MCP tool. Returns the parsed result. Raises on tool error."""
        r = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        result = (r or {}).get("result", {})
        if result.get("isError"):
            text = (result.get("content") or [{}])[0].get("text", "tool error")
            raise SplunkMCPError(f"{name}: {text}")
        # Prefer structuredContent; fall back to parsing content[0].text as JSON.
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        text = (result.get("content") or [{}])[0].get("text", "")
        try:
            return json.loads(text)
        except Exception:
            return {"text": text}

    # --- convenience ------------------------------------------------------
    def run_query(self, spl: str) -> list[dict]:
        """Run SPL via splunk_run_query and return the result rows."""
        out = self.call_tool("splunk_run_query", {"query": spl})
        return out.get("results", []) if isinstance(out, dict) else []


def _smoke() -> None:
    mcp = SplunkMCP()
    info = mcp.initialize()
    print("✅ initialize:", info.get("serverInfo"), "proto", info.get("protocolVersion"))
    tools = mcp.list_tools()
    print(f"✅ tools/list: {len(tools)} tools ->", ", ".join(t["name"] for t in tools))
    spl = sys.argv[1] if len(sys.argv) > 1 else \
        "search index=_internal | head 100 | stats count by sourcetype | head 5"
    rows = mcp.run_query(spl)
    print(f"✅ splunk_run_query returned {len(rows)} rows for: {spl}")
    for row in rows[:5]:
        print("   -", row)


if __name__ == "__main__":
    _smoke()
