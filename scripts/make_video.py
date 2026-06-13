#!/usr/bin/env python3
"""Headless demo-video generator for SOC Sentinel.

Renders the demo as a sequence of PNG frames with Pillow (a glowy title, scrolling
terminal scenes from the real run transcripts, the architecture diagram, and the
risk-ranked report), then stitches them into an MP4 with ffmpeg. No GUI / OBS / display
needed — "run, make a frame, combine", generated programmatically.

    python3 scripts/make_video.py [out.mp4]
"""
import math
import os
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAMEDIR = "/tmp/soc_frames"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/soc_sentinel_demo.mp4"
W, H, FPS = 1280, 720, 24
BG, FG = (13, 18, 23), (208, 214, 222)
FONTDIR = "/usr/share/fonts/truetype/dejavu"
_EMOJI = re.compile(r"[\U0001F000-\U0001FAFF\U00002600-\U000026FF]")


def _font(name, size):
    for n in (name, "DejaVuSansMono.ttf"):
        p = os.path.join(FONTDIR, n)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


MONO = _font("DejaVuSansMono.ttf", 21)
MONO_S = _font("DejaVuSansMono.ttf", 16)
BIG = _font("DejaVuSans-Bold.ttf", 50)
SUB = _font("DejaVuSans.ttf", 26)
TAG = _font("DejaVuSans.ttf", 22)

BLOCK = {
    "S": ["#####", "#    ", "#####", "    #", "#####"], "O": ["#####", "#   #", "#   #", "#   #", "#####"],
    "C": ["#####", "#    ", "#    ", "#    ", "#####"], "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"], "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"], "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    " ": ["     ", "     ", "     ", "     ", "     "],
}
WORD = "SOC SENTINEL"

_n = [0]


def _save(img):
    _n[0] += 1
    img.save(os.path.join(FRAMEDIR, "f%05d.png" % _n[0]))


def _hsv(h, s, v):
    i = int(h * 6) % 6
    f = h * 6 - int(h * 6)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r, g, b = [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)][i]
    return int(r * 255), int(g * 255), int(b * 255)


def _line_color(line):
    pref = {"🔧": ((120, 200, 230), "» "), "📡": ((120, 200, 230), "» "), "🧠": ((235, 205, 95), "◆ "),
            "✅": ((110, 205, 125), "✓ "), "🚫": ((225, 120, 120), "✗ "), "🤖": ((150, 160, 170), "» "),
            "📄": ((150, 160, 170), "» "), "🛡": ((120, 205, 125), "")}
    s = line
    col = FG
    for k, (c, rep) in pref.items():
        if s.lstrip().startswith(k):
            col = c
            s = s.replace(k, rep, 1)
            break
    st = s.strip()
    if st.startswith("[HIGH") or "CONFIRMED" in st:
        col = (110, 205, 125)
    elif st.startswith("[MEDIUM"):
        col = (225, 175, 95)
    elif st.startswith("[LOW") or "REJECTED" in st or st.startswith("[ERROR"):
        col = (200, 150, 120)
    elif st.startswith("──"):
        col = (95, 175, 220)
    elif st.startswith("==") or "UNIVERSAL" in st:
        col = (95, 175, 220)
    return col, _EMOJI.sub("", s)


def _chrome():
    d = Image.new("RGB", (W, H), BG)
    dr = ImageDraw.Draw(d)
    dr.rectangle([0, 0, W, 34], fill=(28, 34, 42))
    for i, c in enumerate([(235, 95, 90), (235, 190, 90), (110, 200, 120)]):
        dr.ellipse([18 + i * 26, 11, 32 + i * 26, 25], fill=c)
    dr.text((W // 2 - 120, 9), "soc-sentinel — splunk agentic ops", font=MONO_S, fill=(150, 160, 170))
    return d, dr


def _clean(s):
    s = s.replace("\t", " ")
    m = re.search(r"(🔧|📡)\s*MCP call:\s*(\w+)\((.*)\)", s)
    if m:
        qm = re.search(r'"query":\s*"([^"]{0,58})', m.group(3))
        prev = (qm.group(1) if qm else m.group(3)[:48]).replace("\\n", " ")
        return f"{m.group(1)} {m.group(2)}   {prev}…"
    return s


def terminal_frame(lines):
    d, dr = _chrome()
    y = 50
    for ln in lines[:23]:
        col, txt = _line_color(ln.rstrip("\n"))
        dr.text((26, y), txt[:94], font=MONO, fill=col)
        y += 27
    _save(d)


def scroll_scene(path, frames, hold_tail=8):
    lines = [_clean(l.rstrip("\n")) for l in open(os.path.join(ROOT, path), encoding="utf-8")]
    lines = [l for l in lines if l.strip()] or [""]
    win = 23
    for fr in range(frames):
        reveal = max(1, int(round((fr + 1) / frames * len(lines))))
        start = max(0, reveal - win)
        terminal_frame(lines[start:reveal])
    for _ in range(hold_tail):
        terminal_frame(lines[max(0, len(lines) - win):])


def title_scene(frames):
    rows = [" ".join(BLOCK.get(c, BLOCK[" "])[r] for c in WORD) for r in range(5)]
    cw = max(len(r) for r in rows)
    cell, ch = 13, 17
    bw = cw * cell
    x0 = (W - bw) // 2
    y0 = 150
    for fr in range(frames):
        d = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(d)
        sweep = (fr * 2.4) % (cw + 26) - 13
        for ri, row in enumerate(rows):
            for ci, c in enumerate(row):
                if c != "#":
                    continue
                hue = ((ci / cw) + fr * 0.026) % 1.0
                v = min(1.0, 0.78 + 0.22 * math.exp(-((ci - sweep) ** 2) / 30.0))
                col = _hsv(hue, 0.85, v)
                x, y = x0 + ci * cell, y0 + ri * ch
                dr.rectangle([x, y, x + cell - 2, y + ch - 2], fill=col)
        # sparkles
        for k in range(60):
            sx = (k * 97 + fr * 13) % W
            sy = (k * 53 + fr * 7) % 130 + 20
            if (k + fr) % 3 == 0:
                dr.text((sx, sy), "✦", font=MONO_S, fill=_hsv(((k + fr) % 30) / 30, 0.5, 0.9))
        pulse = 0.55 + 0.45 * abs(math.sin(fr * 0.22))
        tag = "agentic SOC analyst you can TRUST — code, not the model, decides what's confirmed"
        tw = dr.textlength(tag, font=TAG)
        dr.text(((W - tw) // 2, y0 + 5 * ch + 40), tag, font=TAG,
                fill=(int(90 + 120 * pulse), int(80 + 175 * pulse), int(100 + 110 * pulse)))
        _save(d)


def caption_scene(big, sub, frames, accent=(101, 166, 55)):
    for _ in range(frames):
        d = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(d)
        bw = dr.textlength(big, font=BIG)
        dr.text(((W - bw) // 2, 250), big, font=BIG, fill=(235, 240, 245))
        dr.rectangle([(W - bw) // 2, 320, (W + bw) // 2, 326], fill=accent)
        for i, line in enumerate(sub):
            sw = dr.textlength(line, font=SUB)
            dr.text(((W - sw) // 2, 360 + i * 40), line, font=SUB, fill=(170, 180, 190))
        _save(d)


def image_scene(path, frames, pan=True):
    img = Image.open(os.path.join(ROOT, path)).convert("RGB")
    scale = W / img.width
    img = img.resize((W, int(img.height * scale)))
    for fr in range(frames):
        canvas = Image.new("RGB", (W, H), BG)
        if img.height <= H or not pan:
            canvas.paste(img, (0, max(0, (H - img.height) // 2)))
        else:
            off = int((img.height - H) * (fr / max(1, frames - 1)))
            canvas.paste(img.crop((0, off, W, off + H)), (0, 0))
        _save(canvas)


def main():
    os.makedirs(FRAMEDIR, exist_ok=True)
    for f in os.listdir(FRAMEDIR):
        os.remove(os.path.join(FRAMEDIR, f))

    title_scene(56)                                                         # ~2.3s glowy intro
    caption_scene("The problem", ["AI over your SIEM confidently invents breaches",
                                  "that aren't in the data. In a SOC that's a dealbreaker."], 48, (192, 57, 43))
    caption_scene("SOC Sentinel", ["Claude investigates Splunk via the MCP Server —",
                                   "but CODE, not the model, decides what's confirmed."], 48)
    image_scene("docs/architecture.png", 96, pan=False)                     # 4s architecture
    caption_scene("Live agentic investigation", ["Every search is a real Splunk MCP Server call.",
                                                 "Watch it reason and query live."], 40)
    scroll_scene("artifacts/sample_investigation.txt", 150)                 # the hero: live agent
    caption_scene("The trust gate", ["Every claim traces to a real Splunk row.",
                                     "Unsupported claims are BLOCKED — no hallucinations."], 44, (192, 57, 43))
    image_scene("reports/incident_report.png", 150, pan=True)              # risk-ranked report
    caption_scene("Universal & multi-cloud", ["31 behavioural detectors — AWS, Azure, GCP, endpoint…",
                                              "no hardcoded IOCs, so it works on any environment."], 40)
    scroll_scene("artifacts/sample_hunt.txt", 110)                         # multi-cloud hunt
    caption_scene("Code checks the AI.", ["SOC Sentinel — agentic SOC analysis you can trust.",
                                          "github.com/3sk1nt4n/SOC-Sentinel-Splunk"], 60)

    print("frames:", _n[0], "->", OUT)
    cmd = ["ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(FRAMEDIR, "f%05d.png"),
           "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", OUT]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
