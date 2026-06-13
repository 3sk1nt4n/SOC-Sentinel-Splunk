#!/usr/bin/env python3
"""Headless cinematic demo-video generator for SOC Sentinel.

Renders the demo as PNG frames with Pillow and stitches them into an MP4 with
ffmpeg — no GUI/OBS/display needed. Two acts:
  ACT 1  the problem — an animated flowing architecture chart, the hallucination
         problem, a question, then the answer.
  ACT 2  a real walkthrough — setup steps, the glowy hidden API-key entry, run,
         find the intrusion, respond, and the MITRE risk-ranked report.

Big clean fonts (Ubuntu), slow smooth fade transitions, universal.

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
BG, FG = (12, 16, 22), (210, 216, 224)
BLUE, BLUED, GREEN, GREY = (54, 122, 196), (26, 73, 113), (101, 166, 55), (120, 132, 144)
RED, AMBER = (200, 70, 64), (224, 150, 60)
_EMOJI = re.compile(r"[\U0001F000-\U0001FAFF\U00002600-\U000026FF]")
FD = "/usr/share/fonts/truetype"


def _f(path, size, *alts):
    for p in (path, *alts, FD + "/dejavu/DejaVuSans.ttf"):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


UB = lambda s: _f(FD + "/ubuntu/Ubuntu-B.ttf", s, FD + "/liberation/LiberationSans-Bold.ttf")
UR = lambda s: _f(FD + "/ubuntu/Ubuntu-R.ttf", s, FD + "/liberation/LiberationSans-Regular.ttf")
UM = lambda s: _f(FD + "/ubuntu/UbuntuMono-R.ttf", s, FD + "/dejavu/DejaVuSansMono.ttf")
TITLE, H2, BODY, SMALL = UB(60), UB(40), UR(28), UR(22)
# DejaVu mono for terminals — it has the ✓ ✗ ◆ glyphs Ubuntu Mono lacks.
DM = lambda s: _f(FD + "/dejavu/DejaVuSansMono.ttf", s)
MONO, MONO_S = DM(24), DM(20)

_n = [0]


def _save(im):
    _n[0] += 1
    im.save(os.path.join(FRAMEDIR, "f%05d.png" % _n[0]))


def _smooth(t):
    return t * t * (3 - 2 * t)


def emit(frames, fade=10):
    """Save frames, fading the first/last `fade` of them from/to black (smooth cut)."""
    black = Image.new("RGB", (W, H), (0, 0, 0))
    n = len(frames)
    for i, im in enumerate(frames):
        a = 1.0
        if i < fade:
            a = _smooth((i + 1) / (fade + 1))
        elif i >= n - fade:
            a = _smooth((n - i) / (fade + 1))
        _save(Image.blend(black, im, a) if a < 1 else im)


def canvas():
    return Image.new("RGB", (W, H), BG)


def ctext(dr, cx, y, text, font, fill):
    w = dr.textlength(text, font=font)
    dr.text((cx - w / 2, y), text, font=font, fill=fill)
    return w


def _hsv(h, s, v):
    i = int(h * 6) % 6
    f = h * 6 - int(h * 6)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r, g, b = [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)][i]
    return int(r * 255), int(g * 255), int(b * 255)


# ---------------------------------------------------------------- ACT 1
def node(dr, c, label, sub, fill, w=210, h=74):
    x, y = c
    dr.rounded_rectangle([x - w // 2, y - h // 2, x + w // 2, y + h // 2], 12,
                         fill=fill, outline=(255, 255, 255), width=1)
    ctext(dr, x, y - 22, label, UB(20), (255, 255, 255))
    ctext(dr, x, y + 4, sub, UR(16), (235, 240, 245))


def arrow(dr, p1, p2, color, width=3, dash=False):
    x1, y1 = p1
    x2, y2 = p2
    if dash:
        n = 14
        for k in range(n):
            if k % 2:
                continue
            a = k / n
            b = (k + 1) / n
            dr.line([x1 + (x2 - x1) * a, y1 + (y2 - y1) * a, x1 + (x2 - x1) * b, y1 + (y2 - y1) * b], fill=color, width=width)
    else:
        dr.line([x1, y1, x2, y2], fill=color, width=width)
    ang = math.atan2(y2 - y1, x2 - x1)
    for s in (2.6, -2.6):
        dr.line([x2, y2, x2 - 13 * math.cos(ang + s / 6 * math.pi), y2 - 13 * math.sin(ang + s / 6 * math.pi)], fill=color, width=width)


def _path_pt(pts, t):
    segs = [(pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
    L = [math.dist(a, b) for a, b in segs]
    tot = sum(L) or 1
    d = t * tot
    for (a, b), l in zip(segs, L):
        if d <= l:
            f = d / (l or 1)
            return a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f
        d -= l
    return pts[-1]


def scene_arch_flow(frames=130):
    A = (175, 200); O = (475, 200); M = (775, 200); S = (1075, 200)
    G = (475, 470); R = (775, 470)
    path = [A, O, M, S, M, O, G, R, A]
    out = []
    for fr in range(frames):
        im = canvas()
        dr = ImageDraw.Draw(im)
        ctext(dr, W / 2, 70, "How SOC Sentinel works", UB(34), (235, 240, 245))
        # arrows (dim base)
        arrow(dr, (A[0] + 95, A[1]), (O[0] - 105, O[1]), GREY)
        arrow(dr, (O[0] + 105, O[1]), (M[0] - 105, M[1]), (90, 120, 160))
        arrow(dr, (M[0] + 105, M[1]), (S[0] - 90, S[1]), (70, 120, 80))
        arrow(dr, (S[0] - 90, S[1] + 24), (M[0] + 105, M[1] + 24), (70, 120, 80), 2, dash=True)
        arrow(dr, (O[0], O[1] + 37), (G[0], G[1] - 37), (90, 120, 160))
        arrow(dr, (G[0] + 105, G[1]), (R[0] - 105, R[1]), GREEN)
        arrow(dr, (R[0], R[1] - 37), (A[0] + 60, A[1] + 30), GREY)
        arrow(dr, (G[0] - 105, G[1] - 18), (G[0] - 150, O[1] + 30), RED, 2, dash=True)
        dr.text((250, 330), "blocked", font=UR(15), fill=RED)
        node(dr, A, "ANALYST", "plain-English ask", GREY)
        node(dr, O, "CLAUDE", "orchestrator", BLUE)
        node(dr, M, "SPLUNK MCP", "the AI capability", GREEN)
        node(dr, S, "SPLUNK", "your data", GREEN, w=180)
        node(dr, G, "VALIDATOR", "the trust gate", BLUED)
        node(dr, R, "REPORT", "risk-ranked", BLUE)
        # flowing data pulse ON TOP (trail + bright white core) so the flow reads
        t = _smooth(min(1.0, fr / (frames - 16))) if fr < frames - 1 else 1.0
        rgba = im.convert("RGBA")
        for back, inten in ((0.10, 0.28), (0.05, 0.55), (0.0, 1.0)):
            tx, ty = _path_pt(path, max(0.0, t - back))
            g = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            gd = ImageDraw.Draw(g)
            for rad, al in ((24, 45), (15, 100), (8, 190)):
                gd.ellipse([tx - rad, ty - rad, tx + rad, ty + rad], fill=(150, 226, 255, int(al * inten)))
            rgba = Image.alpha_composite(rgba, g)
        cx, cy = _path_pt(path, t)
        gc = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ImageDraw.Draw(gc).ellipse([cx - 5, cy - 5, cx + 5, cy + 5], fill=(255, 255, 255, 255))
        out.append(Image.alpha_composite(rgba, gc).convert("RGB"))
    return out


def scene_title(frames=70):
    BLK = {"S": ["#####", "#    ", "#####", "    #", "#####"], "O": ["#####", "#   #", "#   #", "#   #", "#####"],
           "C": ["#####", "#    ", "#    ", "#    ", "#####"], "E": ["#####", "#    ", "#### ", "#    ", "#####"],
           "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"], "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
           "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"], "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
           " ": ["     "] * 5}
    rows = [" ".join(BLK.get(c, BLK[" "])[r] for c in "SOC SENTINEL") for r in range(5)]
    cw = max(len(r) for r in rows); cell, ch = 14, 18
    x0 = (W - cw * cell) // 2; y0 = 200
    out = []
    for fr in range(frames):
        im = canvas(); dr = ImageDraw.Draw(im)
        sweep = (fr * 2.4) % (cw + 26) - 13
        for ri, row in enumerate(rows):
            for ci, c in enumerate(row):
                if c == "#":
                    hue = ((ci / cw) + fr * 0.025) % 1.0
                    v = min(1.0, 0.78 + 0.22 * math.exp(-((ci - sweep) ** 2) / 30.0))
                    dr.rectangle([x0 + ci * cell, y0 + ri * ch, x0 + ci * cell + cell - 2, y0 + ri * ch + ch - 2], fill=_hsv(hue, 0.85, v))
        ctext(dr, W / 2, y0 + 5 * ch + 36, "agentic SOC analyst you can TRUST", UB(28), (235, 240, 245))
        ctext(dr, W / 2, y0 + 5 * ch + 78, "code, not the model, decides what's confirmed", UR(22), (150, 162, 174))
        out.append(im)
    return out


def scene_problem(frames=150):
    out = []
    for fr in range(frames):
        im = canvas(); dr = ImageDraw.Draw(im)
        ctext(dr, W / 2, 60, "The problem: AI hallucination", UB(34), (235, 240, 245))
        node(dr, (230, 280), "YOUR LOGS", "in Splunk", GREEN, w=190)
        node(dr, (530, 280), "AI", "reads it all", BLUE, w=150)
        arrow(dr, (325, 280), (455, 280), GREY)
        # AI's confident but FAKE claim appears
        if fr > 36:
            a = min(1.0, (fr - 36) / 26)
            box = [690, 232, 1140, 332]
            dr.rounded_rectangle(box, 12, outline=(int(200 * a), int(70 * a), int(64 * a)), width=2)
            dr.text((706, 246), '"Attacker = 203.0.113.99"', font=UM(22), fill=(int(235 * a), int(120 * a), int(110 * a)))
            dr.text((706, 286), "…invented. NOT in your data.", font=UR(19), fill=(int(200 * a), int(90 * a), int(84 * a)))
            arrow(dr, (605, 280), (688, 280), (160, 70, 66))
            if fr > 70:
                cx, cy = 915, 392
                dr.line([cx - 26, cy - 26, cx + 26, cy + 26], fill=(210, 70, 64), width=8)
                dr.line([cx - 26, cy + 26, cx + 26, cy - 26], fill=(210, 70, 64), width=8)
        ctext(dr, W / 2, 470, "A confident wrong answer is worse than no answer.", UR(26), (200, 150, 120))
        ctext(dr, W / 2, 512, "Acting on a made-up finding wastes hours — or misses the real attack.", UR(20), (150, 162, 174))
        out.append(im)
    return out


def scene_caption(big, subs, frames, accent=GREEN, big_color=(235, 240, 245)):
    out = []
    for _ in range(frames):
        im = canvas(); dr = ImageDraw.Draw(im)
        w = ctext(dr, W / 2, 250, big, TITLE, big_color)
        dr.rectangle([(W - w) / 2, 326, (W + w) / 2, 332], fill=accent)
        for i, s in enumerate(subs):
            ctext(dr, W / 2, 372 + i * 42, s, BODY, (175, 185, 196))
        out.append(im)
    return out


# ---------------------------------------------------------------- terminal
def _clean(s):
    m = re.search(r"(🔧|📡)\s*MCP call:\s*(\w+)\((.*)\)", s)
    if m:
        q = re.search(r'"query":\s*"([^"]{0,52})', m.group(3))
        return f"{m.group(1)} {m.group(2)}   {(q.group(1) if q else m.group(3)[:44])}…".replace("\\n", " ")
    return s.replace("\t", " ")


def _col(line):
    pref = {"🔧": ((120, 200, 235), "» "), "📡": ((120, 200, 235), "» "), "🧠": ((235, 205, 95), "◆ "),
            "✅": ((110, 205, 125), "✓ "), "🚫": ((225, 120, 120), "✗ "), "🤖": ((150, 160, 170), "» "), "📄": ((150, 160, 170), "» ")}
    col = FG; s = line
    for k, (c, r) in pref.items():
        if s.lstrip().startswith(k):
            col, s = c, s.replace(k, r, 1); break
    st = s.strip()
    if st.startswith("[HIGH") or "CONFIRMED" in st: col = (110, 205, 125)
    elif st.startswith("[MEDIUM"): col = (225, 175, 95)
    elif st.startswith("[LOW") or "REJECTED" in st: col = (200, 150, 120)
    elif st.startswith("──") or st.startswith("==") or "UNIVERSAL" in st: col = (95, 175, 220)
    return col, _EMOJI.sub("", s)


def term(lines, title="soc-sentinel — splunk agentic ops"):
    im = canvas(); dr = ImageDraw.Draw(im)
    dr.rectangle([0, 0, W, 38], fill=(26, 32, 40))
    for i, c in enumerate([(235, 95, 90), (235, 190, 90), (110, 200, 120)]):
        dr.ellipse([20 + i * 28, 12, 36 + i * 28, 28], fill=c)
    ctext(dr, W / 2, 9, title, MONO_S, (150, 160, 170))
    y = 56
    for ln in lines[:21]:
        col, txt = _col(ln.rstrip("\n"))
        dr.text((28, y), txt[:86], font=MONO, fill=col)
        y += 30
    return im


def scroll(path, frames, hold=10):
    lines = [_clean(l.rstrip("\n")) for l in open(os.path.join(ROOT, path), encoding="utf-8") if l.strip()] or [""]
    out, win = [], 21
    for fr in range(frames):
        rev = max(1, int(round((fr + 1) / frames * len(lines))))
        out.append(term(lines[max(0, rev - win):rev]))
    out += [term(lines[max(0, len(lines) - win):])] * hold
    return out


def scene_steps():
    """Setup steps as glowy terminal cards."""
    out = []
    seq = [
        ("Step 1 — install", ["$ git clone https://github.com/3sk1nt4n/SOC-Sentinel-Splunk", "$ cd SOC-Sentinel-Splunk", "  (Python stdlib only — nothing to pip-install)"]),
        ("Step 2 — point it at Splunk", ["$ cp .env.example .env", "  SPLUNK_HOST=https://localhost:8089", "  SPLUNK_USER=admin"]),
        ("Step 4 — seed a realistic breach", ["$ python3 src/seed_demo_index.py --reset", "  ingested 397 events over the last 24h", "  ✓ a 6-source ATT&CK intrusion to hunt"]),
    ]
    for title, body in seq:
        lines = [title, ""] + body
        for _ in range(46):
            out.append(term(lines, "soc-sentinel — setup"))
    return out


def scene_keymask():
    """Step 3 — the glowy hidden API-key entry (env -> .env -> API_KEY.txt -> hidden), masked & wiped."""
    out = []
    head = ["Step 3 — your Anthropic API key  (you can't get stuck)", "",
            "  1) ENV VAR     export ANTHROPIC_API_KEY=…",
            "  2) .env file   (gitignored)",
            "  3) API_KEY.txt (gitignored)        <— paste it here",
            "  4) hidden prompt (typed, never shown)", ""]
    key = "sk-ant-api03-Xq7" + "k2" * 6
    # type the key (revealed) then mask to dots then wipe
    for i in range(len(key) + 1):
        out.extend([term(head + [f"  🔑 entering key:  {key[:i]}"], "soc-sentinel — auth")] * 2)
    for i in range(len(key) + 1):
        masked = "•" * i + key[i:]
        out.extend([term(head + [f"  🔑 entering key:  {masked}"], "soc-sentinel — auth")] * 1)
    for _ in range(30):
        out.append(term(head + ["  ✓ key loaded from API_KEY.txt", "  • never echoed to screen   • never written to git"], "soc-sentinel — auth"))
    return out


def _mark(dr, cx, cy, ok, size=24, w=6):
    c = (110, 205, 125) if ok else (210, 80, 72)
    if ok:
        dr.line([cx - size * 0.55, cy + size * 0.05, cx - size * 0.1, cy + size * 0.5], fill=c, width=w)
        dr.line([cx - size * 0.1, cy + size * 0.5, cx + size * 0.6, cy - size * 0.5], fill=c, width=w)
    else:
        dr.line([cx - size * 0.5, cy - size * 0.5, cx + size * 0.5, cy + size * 0.5], fill=c, width=w)
        dr.line([cx - size * 0.5, cy + size * 0.5, cx + size * 0.5, cy - size * 0.5], fill=c, width=w)


def scene_factcheck(frames=175):
    out = []

    def row(dr, y, claim, verdict, ok, show):
        if not show:
            return
        dr.rounded_rectangle([120, y - 36, 615, y + 36], 10, outline=BLUE, width=2)
        dr.text((142, y - 14), claim, font=MONO_S, fill=(212, 218, 226))
        arrow(dr, (620, y), (715, y), GREY)
        col = (110, 205, 125) if ok else (210, 80, 72)
        dr.rounded_rectangle([720, y - 36, 1160, y + 36], 10, outline=col, width=2)
        _mark(dr, 752, y, ok, 26, 6)
        dr.text((792, y - 14), verdict, font=UB(21), fill=col)

    for fr in range(frames):
        im = canvas(); dr = ImageDraw.Draw(im)
        ctext(dr, W / 2, 52, "How SOC Sentinel fixes it", UB(34), (235, 240, 245))
        ctext(dr, W / 2, 104, "It never lets the AI mark its own homework.", UR(22), (150, 162, 174))
        row(dr, 250, 'AI: "attacker IP = 203.0.113.66"', "in your data  ->  KEEP", True, fr > 18)
        row(dr, 400, 'AI: "beacon to 8.8.8.8"', "NOT in data  ->  BLOCK", False, fr > 72)
        if fr > 124:
            ctext(dr, W / 2, 520, "Only evidence-backed findings ever reach you.", UB(26), (110, 205, 125))
        out.append(im)
    return out


def image_scene(path, frames, pan=True):
    img = Image.open(os.path.join(ROOT, path)).convert("RGB")
    img = img.resize((W, int(img.height * (W / img.width))))
    out = []
    for fr in range(frames):
        c = canvas()
        if img.height <= H or not pan:
            c.paste(img, (0, max(0, (H - img.height) // 2)))
        else:
            off = int((img.height - H) * _smooth(fr / max(1, frames - 1)))
            c.paste(img.crop((0, off, W, off + H)), (0, 0))
        out.append(c)
    return out


def main():
    os.makedirs(FRAMEDIR, exist_ok=True)
    for f in os.listdir(FRAMEDIR):
        os.remove(os.path.join(FRAMEDIR, f))

    # ── ACT 1 — the problem ──
    emit(scene_title(64))                                         # glowy title
    emit(image_scene("docs/pipeline.png", 330, pan=True))        # fancy pipeline — slow pan, read step by step
    emit(scene_arch_flow(110))                                    # flowing architecture (data view)
    emit(scene_problem(150))                                      # the hallucination problem
    emit(scene_caption("AI fills gaps with guesses", ["Like an eager intern who writes “a burglar in a red car”", "— when there was no red car."], 90, AMBER))
    emit(scene_caption("Can you trust it?", ["Can you trust what an AI says about your security data?"], 70, RED))
    emit(scene_caption("SOC Sentinel makes sure you can", ["The AI investigates — but CODE checks every claim against the real data."], 80))
    emit(scene_factcheck(175))                                    # keep / block visual
    emit(scene_caption("How sure is it?", ["Seen in 3+ data sources  ->  HIGH  (act now).", "Seen in only one  ->  LOW  (worth a look)."], 85, BLUE))
    # ── ACT 2 — a real walkthrough ──
    emit(scene_caption("Let's see it — for real", ["Set it up, run it, and watch it work end to end."], 56, BLUE))
    emit(scene_steps())
    emit(scene_keymask())                                         # glowy hidden API-key entry
    emit(scene_caption("Run it", ["Claude investigates Splunk live through the MCP Server."], 50, BLUE))
    emit(scroll("artifacts/sample_investigation.txt", 175))       # find the intrusion (live)
    emit(scene_caption("It finds the attack", ["Compromised account, attacker source, lateral movement, exfiltration —", "each claim traced to a real Splunk result."], 85, GREEN))
    emit(scene_caption("…and blocks the guesses", ["Claims the data can't support are BLOCKED — no hallucinations reach you."], 75, RED))
    emit(scene_caption("Clear reporting — MITRE & risk", ["Ranked worst-first, mapped to ATT&CK, with how to fix each one."], 72, GREEN))
    emit(image_scene("reports/incident_report.png", 175, pan=True))
    emit(scene_caption("Universal & multi-cloud", ["31 behavioural detectors — AWS, Azure, GCP, endpoint, identity, network.", "No hardcoded IOCs: it works on any environment."], 85, BLUE))
    emit(scroll("artifacts/sample_hunt.txt", 120))
    emit(scene_caption("In one sentence", ["The AI does the thinking. The code checks the facts.", "Nothing made-up ever reaches your report."], 105, GREEN))
    emit(scene_caption("Code checks the AI.", ["SOC Sentinel — agentic SOC analysis you can trust.", "github.com/3sk1nt4n/SOC-Sentinel-Splunk"], 80))

    print("frames:", _n[0])
    subprocess.run(["ffmpeg", "-y", "-framerate", str(FPS), "-i", os.path.join(FRAMEDIR, "f%05d.png"),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", OUT],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
