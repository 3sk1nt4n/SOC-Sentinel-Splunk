"""Anthropic API-key resolution — ported from Sentinel Ensemble's "you can't get
stuck" design. Checks, in order, and a real key always beats a placeholder:

  1. env var   ANTHROPIC_API_KEY
  2. .env       ANTHROPIC_API_KEY=...        (gitignored)
  3. API_KEY.txt  (repo root, last real line) (gitignored, auto-created)
  4. hidden CLI prompt (getpass — never echoed, session-only, not saved)

The key is validated by shape and is never printed or logged."""
from __future__ import annotations

import os
import sys
from getpass import getpass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_env  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TXT_PATH = os.path.join(_REPO_ROOT, "API_KEY.txt")
_PLACEHOLDER_HINT = (
    "# Paste your Anthropic API key on the last line (starts with sk-ant-).\n"
    "# This file is gitignored and never committed. Or use the env var / .env / hidden prompt.\n"
)


def _looks_real(k: str | None) -> bool:
    if not isinstance(k, str):
        return False
    k = k.strip()
    return k.startswith("sk-ant-") and "..." not in k and len(k) > 24


def _ensure_txt_stub() -> None:
    if not os.path.exists(_TXT_PATH):
        try:
            with open(_TXT_PATH, "w", encoding="utf-8") as f:
                f.write(_PLACEHOLDER_HINT)
        except OSError:
            pass


def resolve_key(interactive: bool = True) -> tuple[str, str]:
    """Return (key, source_label). Raises RuntimeError if none can be obtained."""
    # 1. environment
    k = os.environ.get("ANTHROPIC_API_KEY")
    if _looks_real(k):
        return k.strip(), "env var"

    # 2. .env
    k = load_env().get("ANTHROPIC_API_KEY")
    if _looks_real(k):
        return k.strip(), ".env"

    # 3. API_KEY.txt (last real line)
    if os.path.isfile(_TXT_PATH):
        for line in reversed(open(_TXT_PATH, encoding="utf-8").read().splitlines()):
            if _looks_real(line):
                return line.strip(), "API_KEY.txt"

    # 4. hidden prompt
    if interactive and sys.stdin.isatty():
        entered = getpass("🔑 Anthropic API key (hidden — session only, not saved): ").strip()
        if _looks_real(entered):
            return entered, "hidden prompt"

    _ensure_txt_stub()
    raise RuntimeError(
        "No valid ANTHROPIC_API_KEY found. Provide it any of 4 ways:\n"
        "  1) export ANTHROPIC_API_KEY=sk-ant-...\n"
        "  2) add ANTHROPIC_API_KEY=sk-ant-... to .env\n"
        f"  3) paste it on the last line of {_TXT_PATH}\n"
        "  4) run interactively and paste at the hidden prompt.\n"
        "Get a key at https://console.anthropic.com")


if __name__ == "__main__":
    try:
        key, src = resolve_key(interactive=False)
        print(f"✅ key resolved from: {src}  (…{key[-4:]})")
    except RuntimeError as e:
        print(e)
