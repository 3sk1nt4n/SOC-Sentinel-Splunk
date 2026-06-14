#!/usr/bin/env python3
"""Animated 'dancy glowy' intro banner for SOC Sentinel.

Truecolor 'SOC SENTINEL' with a different colour scheme every run (3 palettes +
random hue offset). On a TTY it animates a couple of seconds then settles; with
--static (or when piped / non-TTY) it prints ONE clean frame and exits — used by
the onboarding so it never floods the scrollback."""
import math
import os
import random
import sys
import time

FONT = {
    "S": ["#####", "#    ", "#####", "    #", "#####"],
    "O": ["#####", "#   #", "#   #", "#   #", "#####"],
    "C": ["#####", "#    ", "#    ", "#    ", "#####"],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    " ": ["     ", "     ", "     ", "     ", "     "],
}
WORD = "SOC SENTINEL"
ROWS = 5
RST = "\x1b[0m"
SPARK = "✦✧⋆·°"


def _rows():
    return [" ".join(FONT.get(ch, FONT[" "])[r] for ch in WORD) for r in range(ROWS)]


def _hsv(h, s, v):
    h %= 1.0
    i = int(h * 6) % 6
    f = h * 6 - int(h * 6)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r, g, b = [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)][i]
    return int(r * 255), int(g * 255), int(b * 255)


def _fg(rgb):
    return f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def _palette(idx, base):
    """3 distinct schemes; `base` randomises the exact mix each run."""
    if idx == 0:        # full rainbow
        return lambda c, f: _hsv(c + f * 0.026 + base, 0.85, 1.0)
    if idx == 1:        # cyber — cyan / blue / magenta
        return lambda c, f: _hsv(0.62 + 0.22 * math.sin((c * 2.6 + f * 0.12 + base) * math.pi), 0.82, 1.0)
    return lambda c, f: _hsv(0.34 + 0.18 * math.sin((c * 2.0 + f * 0.10 + base) * math.pi), 0.88, 1.0)  # neon green/teal


def main():
    static = "--static" in sys.argv
    tty = sys.stdout.isatty() and not static
    random.seed()                              # different every run
    pal = _palette(random.randint(0, 2), random.random())
    rows = _rows()
    width = max(len(r) for r in rows)
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 90
    pad = max(0, (cols - width) // 2)
    frames = 46 if tty else 1
    w = sys.stdout.write
    if tty:
        w("\x1b[?25l")
    try:
        for frame in range(frames):
            if tty:
                w("\x1b[H\x1b[2J")
            w("\n")
            spark = "".join((_fg(_hsv(random.random(), 0.6, 0.95)) + random.choice(SPARK))
                            if random.random() < 0.22 else " " for _ in range(min(cols - 1, width + 2 * pad)))
            w(spark + RST + "\n\n")
            sweep = (frame * 2.2) % (width + 24) - 12
            for row in rows:
                line = " " * pad
                for ci, ch in enumerate(row):
                    if ch == " ":
                        line += " "
                        continue
                    v = min(1.0, 0.82 + 0.18 * math.exp(-((ci - sweep) ** 2) / 36.0)) if tty else \
                        min(1.0, 0.78 + 0.22 * (ci / max(1, width)))
                    line += _fg(pal(ci / max(1, width), frame)) + "█"
                w(line + RST + "\n")
            tag = "agentic SOC analyst you can TRUST  —  code, not the model, decides what's confirmed"
            w("\n" + " " * max(0, (cols - len(tag) - 4) // 2) + _fg(pal(0.5, frame)) + "🛡  " + tag + RST + "\n")
            sys.stdout.flush()
            if tty:
                time.sleep(0.055)
    finally:
        if tty:
            w("\x1b[?25h")
        w(RST + "\n")


if __name__ == "__main__":
    main()
