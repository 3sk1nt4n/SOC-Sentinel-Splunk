#!/usr/bin/env python3
"""Animated 'dancy glowy' intro banner for the SOC Sentinel demo.

Truecolor (24-bit) rainbow gradient that drifts, a moving glow sweep, and
twinkling sparkles — pure terminal, no dependencies. On a TTY it animates for a
couple of seconds then settles; piped/non-TTY it renders a single still frame."""
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
    i = int(h * 6)
    f = h * 6 - i
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r, g, b = [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)][i % 6]
    return int(r * 255), int(g * 255), int(b * 255)


def _fg(r, g, b):
    return f"\x1b[38;2;{r};{g};{b}m"


def main():
    tty = sys.stdout.isatty()
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
            spark = "".join(
                (_fg(*_hsv(random.random(), 0.6, 0.95)) + random.choice(SPARK))
                if random.random() < 0.22 else " " for _ in range(min(cols - 1, width + 2 * pad)))
            w(" " * 0 + spark + RST + "\n\n")
            sweep = (frame * 2.2) % (width + 24) - 12
            for row in rows:
                line = " " * pad
                for ci, ch in enumerate(row):
                    if ch == " ":
                        line += " "
                        continue
                    hue = ((ci / max(1, width)) + frame * 0.028) % 1.0
                    v = min(1.0, 0.8 + 0.2 * math.exp(-((ci - sweep) ** 2) / 36.0))
                    line += _fg(*_hsv(hue, 0.85, v)) + "█"
                w(line + RST + "\n")
            pulse = 0.55 + 0.45 * abs(math.sin(frame * 0.22))
            tr, tg, tb = int(90 + 120 * pulse), int(70 + 180 * pulse), int(90 + 110 * pulse)
            tag = "agentic SOC analyst you can TRUST  —  code, not the model, decides what's confirmed"
            w("\n" + " " * max(0, (cols - len(tag) - 4) // 2) + _fg(tr, tg, tb) + "🛡  " + tag + RST + "\n")
            sys.stdout.flush()
            if tty:
                time.sleep(0.055)
    finally:
        if tty:
            w("\x1b[?25h")
        w(RST + "\n")


if __name__ == "__main__":
    main()
