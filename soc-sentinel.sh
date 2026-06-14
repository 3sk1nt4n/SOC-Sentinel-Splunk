#!/usr/bin/env bash
# SOC Sentinel — one-command front door: health checks, hidden API-key paste, run.
cd "$(dirname "$0")" || exit 1
exec python3 src/onboard.py "$@"
