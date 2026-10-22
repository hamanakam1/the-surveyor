"""Local machine identity.

Every layer of the map has to agree on which host it is describing, otherwise
``power`` edges point at a host node that ``network`` never created. This
module is the single source of that identity.
"""

from __future__ import annotations

import os
import socket

from .util import slug


def hostname() -> str:
    """Short hostname, stable across platforms and DNS suffixes."""

    candidates = []
    try:
        candidates.append(socket.gethostname())
    except OSError:  # pragma: no cover - exotic environments
        pass
    try:
        candidates.append(os.uname().nodename)
    except (AttributeError, OSError):  # pragma: no cover - Windows
        pass
    for candidate in candidates:
        name = (candidate or "").split(".")[0].strip()
        if name:
            return name
    return "localhost"


def host_id() -> str:
    return f"host:{slug(hostname())}"
