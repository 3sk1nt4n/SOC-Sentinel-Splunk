#!/usr/bin/env bash
# SOC Sentinel — push-button demo player for screen recording (OBS + mic).
#
# Run this in a large terminal while OBS records your screen. It prints section
# banners + narration cues, "types" each command, pauses for you to narrate
# (press Enter), then runs it LIVE. Follows docs/DEMO_SCRIPT.md.
#
#   ./scripts/demo.sh           # full live demo (uses API_KEY.txt + Haiku)
#   DEMO_FAST=1 ./scripts/demo.sh   # no typing delay (rehearse/timing)
#
# Tips: terminal font ~18-20pt, dark theme, window maximised. Open
# reports/incident_report.html and docs/architecture.png in a browser tab ready
# to switch to after Section 3.
set -u
cd "$(dirname "$0")/.." || exit 1

BLUE=$'\e[1;34m'; GRN=$'\e[1;32m'; DIM=$'\e[2m'; YEL=$'\e[1;33m'; RST=$'\e[0m'
DELAY=${DEMO_FAST:+0}; DELAY=${DELAY-0.018}

banner() { printf '\n%s══════════════════════════════════════════════════════════════%s\n' "$BLUE" "$RST"
           printf '%s  %s%s\n' "$BLUE" "$1" "$RST"
           printf '%s══════════════════════════════════════════════════════════════%s\n\n' "$BLUE" "$RST"; }
say()   { printf '%s🎙  %s%s\n\n' "$DIM" "$1" "$RST"; }
type_out() { local s="$1" i; for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; [ "$DELAY" != 0 ] && sleep "$DELAY"; done; printf '\n'; }
step()  { printf '%s$ %s' "$GRN" "$RST"; type_out "$1"; read -rsp "$(printf '%s  ▸ Enter to run…%s' "$DIM" "$RST")"; printf '\n\n'; }
beat()  { read -rsp "$(printf '%s  ▸ Enter to continue…%s' "$DIM" "$RST")"; printf '\n'; }

clear
banner "SOC Sentinel — an agentic SOC analyst you can TRUST"
say "Point an AI at your SIEM and it confidently invents breaches that aren't in the data."
say "SOC Sentinel: Claude investigates Splunk via the MCP Server — but CODE, not the model, decides what's confirmed."
say "(Open docs/architecture.png to show the flow.)"
beat

banner "1 · LIVE agentic investigation — every search is a real Splunk MCP call"
say "Watch the 🔧 MCP call lines — that's Claude querying Splunk live, no mock data."
step 'env -u ANTHROPIC_API_KEY python3 src/agent.py "Investigate suspicious authentication, privilege escalation and outbound activity in index=soc_demo. Find the compromised account, the attacker, and any exfiltration."'
env -u ANTHROPIC_API_KEY python3 src/agent.py "Investigate suspicious authentication, privilege escalation and outbound activity in index=soc_demo. Find the compromised account, the attacker, and any exfiltration."

banner "2 · The trust gate"
say "Each confirmed finding's claims trace to real Splunk rows; confidence = how many independent sources agree."
say "Anything in 'Blocked by the validator' is a claim the model asserted but the data didn't support — the gate kept it out."
say "Now switch to the browser: open reports/incident_report.html — exec summary, MITRE matrix, risk-ranked table, remediation + the SPL that reproduces each finding."
beat

banner "3 · Universal & multi-cloud — 31 behavioural detectors, no answer keys"
say "Across identity, endpoint, network, AWS, Azure and GCP — detecting BEHAVIOUR, so it works on any environment."
step 'python3 src/agent.py --hunt'
python3 src/agent.py --hunt

banner "4 · Why it wins"
say "Live Splunk AI at runtime + a novel, auditable trust layer. Code checks the AI. That's SOC Sentinel."
say "(Optional: show http://localhost:8000 → the Splunk MCP Server app to prove the Splunk side.)"
printf '\n%sDemo complete.%s\n' "$GRN" "$RST"
