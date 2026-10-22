"""The banner: a theodolite, a sightline, and a plat title block.

ASCII art in a README is decoration; ASCII art printed by the binary is
branding that also explains the tool. Both come from this one source so they
cannot drift apart.

The scene is deliberately literal: a levelled instrument on a tripod, sighting
a four-node graph. "Not to scale" is the honest caveat every survey plat
carries, and the only joke the software needs to make about itself.
"""

from __future__ import annotations

from typing import Any

#: Twelve lines, 69 columns. Keep the left gutter at 10 columns and the
#: wordmark on line 1 if you edit this.
BANNER: tuple[str, ...] = (
    "          T H E   S U R V E Y O R                     O E T   1 . 0",
    "          ───────────────────────────────────────────────────────────",
    "                .-\"\"\"\"\"-.",
    "              .'   ___   '.                    ●───────●",
    "             /    /   \\    \\                  /         \\",
    "            |    | === |    |  ─ ─ ─ ─ ─ ─▶  ●           ●",
    "             \\    \\___/    /                  \\         /",
    "              '.    |    .'                    ●───────●",
    "                '-..|..-'",
    "                   |||                        plat no. 007",
    "            ______|||______                  not to scale",
    "           /   /       \\   \\",
    "          /   /         \\   \\",
    "         '___'           '___'",
)

TAGLINE = "Infrastructure is empirical. The Surveyor takes bearings."

LEGEND = "◆ power   ▣ bare metal   ⌁ network   ■ workloads   ◦ listening socket"

SHORT = "◎ the-surveyor"

_GREEN = "\033[32m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def banner(*, color: bool = False) -> str:
    """Return the banner, optionally with the sightline and graph in green."""

    if not color:
        return "\n".join(BANNER)
    lines: list[str] = []
    for line in BANNER:
        if "●" in line or "─ ─" in line:
            lines.append(_GREEN + line + _RESET)
        elif "T H E" in line:
            lines.append(_BOLD + line + _RESET)
        elif "plat no." in line or "not to scale" in line:
            lines.append(_DIM + line + _RESET)
        else:
            lines.append(line)
    return "\n".join(lines)


def supports_color(stream: Any) -> bool:
    """Honour NO_COLOR, then FORCE_COLOR, then ask the stream."""

    import os

    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())
