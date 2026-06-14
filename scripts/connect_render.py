#!/usr/bin/env python3
"""Render a junior-friendly 'how SOC Sentinel connects to YOUR Splunk' diagram (PNG).

Shows the data flow: your logs -> Splunk -> the Splunk MCP Server (the safe doorway)
-> SOC Sentinel (Claude + the 3-layer validator) -> trustworthy answers. Emphasises
what the MCP Server does and the 3 things you add to connect your own system."""
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

W, H = 1280, 720
BG = (12, 16, 22)
GREEN, BLUE, GREY, AMBER, SLATE = (101, 166, 55), (54, 122, 196), (110, 120, 134), (224, 168, 60), (70, 80, 96)


def ctext(dr, cx, y, t, f, fill):
    dr.text((cx - dr.textlength(t, font=f) / 2, y), t, font=f, fill=fill)


def box(dr, cx, cy, w, h, fill, title, sub, tcol=(255, 255, 255), scol=(235, 240, 245)):
    dr.rounded_rectangle([cx - w // 2, cy - h // 2, cx + w // 2, cy + h // 2], 14,
                         fill=fill, outline=(255, 255, 255), width=1)
    ctext(dr, cx, cy - (24 if sub else 10), title, UB(21), tcol)
    if sub:
        ctext(dr, cx, cy + 6, sub, UR(15), scol)


def arrow(dr, p1, p2, color, label="", width=4):
    import math
    x1, y1 = p1
    x2, y2 = p2
    dr.line([x1, y1, x2, y2], fill=color, width=width)
    a = math.atan2(y2 - y1, x2 - x1)
    for s in (0.5, -0.5):
        dr.line([x2, y2, x2 - 16 * math.cos(a + s), y2 - 16 * math.sin(a + s)], fill=color, width=width)
    if label:
        ctext(dr, (x1 + x2) / 2, min(y1, y2) - 24, label, UR(14), (160, 172, 184))


def render():
    im = Image.new("RGB", (W, H), BG)
    dr = ImageDraw.Draw(im)
    ctext(dr, W / 2, 34, "How SOC Sentinel connects to YOUR Splunk", UB(34), (235, 240, 245))
    ctext(dr, W / 2, 78, "Your logs are already in Splunk. The MCP Server is the safe doorway the AI uses to read them.", UR(19), (150, 162, 174))

    cy = 250
    # 1. your logs feeding splunk
    src = ["firewall", "logins / AD", "cloud (AWS/Azure/GCP)", "endpoints / Sysmon"]
    for i, s in enumerate(src):
        y = 175 + i * 42
        dr.rounded_rectangle([40, y - 16, 235, y + 16], 9, fill=(26, 32, 42), outline=SLATE, width=1)
        ctext(dr, 137, y - 9, s, UR(15), (190, 200, 210))
        arrow(dr, (238, y), (300, cy + (i - 1.5) * 12), GREY, width=2)
    ctext(dr, 137, 150, "1 · YOUR LOGS", UB(16), (150, 162, 174))

    box(dr, 400, cy, 180, 96, GREEN, "SPLUNK", "your indexes", )
    arrow(dr, (492, cy), (610, cy), GREEN, "SPL search")
    box(dr, 710, cy, 200, 110, GREEN, "SPLUNK MCP", "the AI capability")
    # badge on the MCP box
    dr.rounded_rectangle([710 - 86, cy - 64, 710 + 86, cy - 40], 10, fill=AMBER)
    ctext(dr, 710, cy - 61, "THE SAFE DOORWAY", UB(13), (30, 24, 8))
    arrow(dr, (612, cy + 36), (492, cy + 36), GREEN, "", 2)   # result rows back
    arrow(dr, (812, cy), (945, cy), BLUE, "MCP tool call")
    box(dr, 1080, cy, 220, 110, BLUE, "SOC SENTINEL", "Claude + 3-layer validator")
    arrow(dr, (1080, cy + 56), (1080, cy + 150), BLUE, "")
    box(dr, 1080, cy + 200, 220, 70, (26, 32, 42), "Trustworthy answers", "for your analyst", (235, 240, 245), (160, 172, 184))

    # MCP role callout
    cx0 = 560
    dr.rounded_rectangle([cx0, 470, cx0 + 560, 600], 12, fill=(20, 28, 22), outline=GREEN, width=2)
    ctext(dr, cx0 + 280, 484, "What the Splunk MCP Server does", UB(18), (150, 210, 120))
    for i, ln in enumerate(["• typed tools only (splunk_run_query, …) — no shell",
                            "• read-only search — can't change or delete anything",
                            "• token auth + rate limits",
                            "• the AI never touches Splunk directly"]):
        dr.text((cx0 + 24, 514 + i * 21), ln, font=UR(15), fill=(200, 210, 218))

    # what you add
    dr.rounded_rectangle([40, 470, 540, 600], 12, fill=(22, 26, 34), outline=BLUE, width=2)
    ctext(dr, 290, 484, "To connect your own Splunk, you add 3 things", UB(17), (120, 175, 230))
    for i, ln in enumerate(["1 · install the Splunk MCP Server app (Splunkbase 7931)",
                            "2 · point SOC Sentinel at your Splunk in .env",
                            "3 · add your Anthropic API key  ->  run it on YOUR index"]):
        dr.text((64, 516 + i * 23), ln, font=UR(15), fill=(200, 210, 218))

    ctext(dr, W / 2, 648, "read-only · no shell · the validator checks every answer against your real Splunk rows",
          UR(16), (140, 152, 164))
    return im


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "connect.png")
    render().save(out)
    print("wrote", out, render().size)
