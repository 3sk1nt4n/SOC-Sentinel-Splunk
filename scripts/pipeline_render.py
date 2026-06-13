#!/usr/bin/env python3
"""Render the SOC Sentinel pipeline as a fancy, colorful boxed diagram (PNG).

Vertical pipeline of step cards with dotted connectors, colour-coded by role —
setup/grey, Splunk/green, AI steps (glowing cyan), the 3-layer validator
(highlighted gold = the differentiator), report/green, and the --hunt branch
(purple). Importable: render() returns the tall PIL image used by the video."""
import os

from PIL import Image, ImageDraw, ImageFont

FD = "/usr/share/fonts/truetype"


def _f(p, s, *alt):
    for q in (p, *alt, FD + "/dejavu/DejaVuSans.ttf"):
        if os.path.exists(q):
            return ImageFont.truetype(q, s)
    return ImageFont.load_default()


UB = lambda s: _f(FD + "/ubuntu/Ubuntu-B.ttf", s, FD + "/liberation/LiberationSans-Bold.ttf")
UR = lambda s: _f(FD + "/ubuntu/Ubuntu-R.ttf", s, FD + "/liberation/LiberationSans-Regular.ttf")
DM = lambda s: _f(FD + "/dejavu/DejaVuSansMono.ttf", s)
DS = lambda s: _f(FD + "/dejavu/DejaVuSans-Bold.ttf", s)

BG = (12, 16, 22)
GREY, GREEN, BLUE, AMBER, PURPLE, SLATE = (96, 106, 120), (101, 166, 55), (54, 122, 196), (224, 168, 60), (138, 96, 184), (92, 104, 124)

# (accent, badge, badge_font, title, [lines], ai_glow, highlight)
STEPS = [
    (GREY, "0", "n", "SETUP", ["key: env -> .env -> API_KEY.txt -> hidden prompt (never echoed/committed)", "model locked to Haiku - cost-safe"], False, False),
    (GREEN, "1", "n", "CONNECT — Splunk MCP Server", ["mint aud=mcp token  -  MCP initialize / tools-list", "10 typed Splunk tools  -  never a shell"], False, False),
    (SLATE, "2", "n", "ANALYST ASK — a real SOC question", ['e.g.  "Was anything compromised in the last 24h? Show me the high-risk alerts."'], False, False),
    (BLUE, "✦", "s", "AI · INVESTIGATION LOOP  (ReAct)", ["reason -> act -> observe — Claude runs SPL via the MCP Server", "every result row accumulated + tagged by sourcetype"], True, False),
    (BLUE, "✦", "s", "AI · FINALIZE", ["draft findings:  title · MITRE technique · tactic · claims (field=value)"], True, False),
    (AMBER, "★", "s", "3-LAYER VALIDATOR — code checks the AI", ["L1 TRACE        every claim -> a REAL Splunk result row", "L2 CORROBORATE  count independent sourcetypes", "L3 CALIBRATE    3+ = HIGH · 2 = MEDIUM · 1 = LOW"], False, True),
    (BLUE, "6", "n", "RISK RANKING  (deterministic)", ["risk = confidence × corroboration × tactic impact  ->  0-100, worst first"], False, False),
    (GREEN, "7", "n", "REPORT", ["risk-ranked · ATT&CK matrix · remediation + the re-runnable SPL", "Markdown + styled HTML · 'Blocked by the validator' section"], False, False),
    (PURPLE, "H", "n", "alternate entry:  --hunt", ["40+ universal behavioural detectors · 7 domains · full ATT&CK kill chain", "incl. injection · hollowing · cred-dump · anti-forensics — no hardcoded IOCs"], False, False),
]

W = 1240
MX = 40
BW = W - 2 * MX
BH, GAP = 132, 30
HEADER_Y, HEADER_H = 34, 96
TOP = HEADER_Y + HEADER_H + 34
H = TOP + len(STEPS) * (BH + GAP) + 70


def _ctext(dr, cx, y, t, f, fill):
    dr.text((cx - dr.textlength(t, font=f) / 2, y), t, font=f, fill=fill)


def _dotted(dr, x, y1, y2, color=(86, 98, 112), r=3, gap=12):
    y = y1
    while y < y2:
        dr.ellipse([x - r, y - r, x + r, y + r], fill=color)
        y += gap


def _badge_font(kind, s):
    return {"n": UB(s), "s": DS(s)}[kind]


def _box(im, dr, x, y, accent, badge, bk, title, lines, ai, hl):
    dr.rounded_rectangle([x + 3, y + 5, x + BW + 3, y + BH + 5], 18, fill=(0, 0, 0))
    dr.rounded_rectangle([x, y, x + BW, y + BH], 18, fill=(23, 29, 39), outline=(52, 62, 76), width=1)
    dr.rounded_rectangle([x, y, x + 13, y + BH], 7, fill=accent)
    if ai:
        for k, col in ((6, (60, 150, 200)), (3, (110, 215, 245))):
            dr.rounded_rectangle([x - 0, y - 0, x + BW, y + BH], 18, outline=col, width=2)
    if hl:
        dr.rounded_rectangle([x, y, x + BW, y + BH], 18, outline=AMBER, width=3)
        dr.rounded_rectangle([x + BW - 196, y - 14, x + BW - 8, y + 14], 11, fill=AMBER)
        dr.text((x + BW - 188, y - 11, ), "★", font=DS(17), fill=(30, 24, 8))
        _ctext(dr, x + BW - 92, y - 11, "THE DIFFERENTIATOR", UB(14), (30, 24, 8))
    bx, by = x + 62, y + BH // 2
    dr.ellipse([bx - 27, by - 27, bx + 27, by + 27], fill=accent, outline=(255, 255, 255), width=1)
    _ctext(dr, bx, by - 17, badge, _badge_font(bk, 26 if bk == "n" else 24), (255, 255, 255))
    tx = x + 118
    dr.text((tx, y + 16), title, font=UB(25), fill=(236, 241, 246))
    yy = y + 54
    bf = DM(17) if (hl or lines and "->" in lines[0]) else UR(19)
    bf = DM(17) if hl else UR(19)
    for ln in lines:
        dr.text((tx, yy), ln, font=bf, fill=(168, 179, 191))
        yy += 25


def render():
    im = Image.new("RGB", (W, H), BG)
    dr = ImageDraw.Draw(im)
    # header — horizontal gradient blue->green
    for i in range(BW):
        f = i / BW
        c = (int(44 + (101 - 44) * f), int(108 + (166 - 108) * f), int(176 + (55 - 176) * f))
        dr.line([MX + i, HEADER_Y, MX + i, HEADER_Y + HEADER_H], fill=c)
    dr.rounded_rectangle([MX, HEADER_Y, MX + BW, HEADER_Y + HEADER_H], 16, outline=(255, 255, 255), width=1)
    _ctext(dr, W / 2, HEADER_Y + 20, "SOC SENTINEL — PIPELINE", UB(34), (255, 255, 255))
    _ctext(dr, W / 2, HEADER_Y + 62, "agent.py conducts every step · the AI acts only inside the ✦ brackets", UR(19), (240, 245, 248))
    y = TOP
    for i, (accent, badge, bk, title, lines, ai, hl) in enumerate(STEPS):
        if i:
            _dotted(dr, W / 2, y - GAP + 4, y - 4, (190, 150, 70) if STEPS[i][6] or STEPS[i - 1][6] else (86, 98, 112))
        _box(im, dr, MX, y, accent, badge, bk, title, lines, ai, hl)
        y += BH + GAP
    _ctext(dr, W / 2, H - 46, "read-only search · no shell · no destructive ops    —    the validator is the trust boundary",
           UR(18), (140, 152, 164))
    return im


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "pipeline.png")
    render().save(out)
    print("wrote", out, render().size)
