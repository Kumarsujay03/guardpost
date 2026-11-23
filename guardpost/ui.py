"""Terminal colours (only when writing to a terminal) in the cyan HUD style."""
import os
import re
import sys

COLOR = (sys.stdout.isatty() or "FORCE_COLOR" in os.environ) and "NO_COLOR" not in os.environ


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if COLOR else s


def h1(s: str) -> str: return _c("1;96", f"[ {s} ]")
def h2(s: str) -> str: return _c("96", f"-- {s}")
def red(s: str) -> str: return _c("1;91", s)
def yellow(s: str) -> str: return _c("93", s)
def green(s: str) -> str: return _c("92", s)
def dim(s: str) -> str: return _c("2", s)
def bold(s: str) -> str: return _c("1", s)


def strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)
