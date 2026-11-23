#!/usr/bin/env python3
"""Turn coloured terminal output into an SVG "screenshot" for the README.

    FORCE_COLOR=1 guardpost scan x | tools/ansi2svg.py "guardpost scan x" > docs/scan.svg
"""
import html
import re
import sys

COLORS = {"91": "#ff5c6c", "92": "#4ade80", "93": "#facc15", "96": "#22d3ee", "2": "#6b7f8e"}
FG, BG, LINE = "#d7e3ea", "#071018", "#22d3ee"
CW, LH, PAD, TOP = 8.4, 19, 22, 46


def spans(line: str):
    out, style = [], {"color": None, "bold": False, "dim": False}
    for part in re.split(r"(\033\[[0-9;]*m)", line):
        m = re.match(r"\033\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    style = {"color": None, "bold": False, "dim": False}
                elif code == "1":
                    style["bold"] = True
                elif code == "2":
                    style["dim"] = True
                elif code in COLORS:
                    style["color"] = COLORS[code]
        elif part:
            out.append((part, dict(style)))
    return out


def main():
    title = sys.argv[1] if len(sys.argv) > 1 else "guardpost"
    lines = [l.rstrip("\n") for l in sys.stdin][:60]
    lines = [l if len(re.sub(r"\033\[[0-9;]*m", "", l)) <= 104 else l[:104 + (len(l) - len(re.sub(r"\033\[[0-9;]*m", "", l)))] + "\033[0m…" for l in lines]
    width = int(max([len(re.sub(r"\033\[[0-9;]*m", "", l)) for l in lines] + [60]) * CW + 2 * PAD)
    height = int(TOP + len(lines) * LH + PAD)
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
         f'font-family="JetBrains Mono, Fira Code, DejaVu Sans Mono, Menlo, Consolas, monospace" font-size="14">',
         f'<rect width="{width}" height="{height}" rx="6" fill="{BG}"/>',
         f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="6" fill="none" stroke="{LINE}" stroke-opacity="0.35"/>']
    # HUD corner brackets
    b = 14
    for x, y, dx, dy in ((4, 4, 1, 1), (width - 4, 4, -1, 1), (4, height - 4, 1, -1), (width - 4, height - 4, -1, -1)):
        o.append(f'<path d="M{x},{y + dy * b} V{y} H{x + dx * b}" fill="none" stroke="{LINE}" stroke-width="2"/>')
    o.append(f'<line x1="{PAD}" y1="32" x2="{width - PAD}" y2="32" stroke="{LINE}" stroke-opacity="0.25"/>')
    o.append(f'<text x="{PAD}" y="22" fill="{LINE}" font-size="12">$ {html.escape(title)}</text>')
    for i, line in enumerate(lines):
        y = TOP + 6 + i * LH
        col = 0
        for text, st in spans(line):
            # each piece at its exact column and width, so any renderer
            # (browsers, GitHub's image proxy) lines it up like a terminal
            lead = len(text) - len(text.lstrip(" "))
            body = text.strip(" ")
            if body:
                color = st["color"] or ("#6b7f8e" if st["dim"] else FG)
                bold = ' font-weight="bold"' if st["bold"] else ""
                x = PAD + (col + lead) * CW
                o.append(f'<text x="{x:.1f}" y="{y}" fill="{color}"{bold} textLength="{len(body) * CW:.1f}" '
                         f'lengthAdjust="spacingAndGlyphs">{html.escape(body)}</text>')
            col += len(text)
    o.append("</svg>")
    print("\n".join(o))


if __name__ == "__main__":
    main()
