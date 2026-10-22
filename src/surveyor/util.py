"""Small shared helpers: canonical JSON, hashing, and human formatting."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for every digest in The Surveyor.

    Keys are sorted, separators are tight, and non-JSON scalars fall back to
    ``str``. Two machines surveying the same facts must produce the same bytes.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(value: Any) -> str:
    """``sha256:<hex>`` digest of a canonicalisable value."""

    return "sha256:" + sha256_hex(canonical_json(value))


def short_digest(digest: str, length: int = 12) -> str:
    body = digest.split(":", 1)[-1]
    return body[:length]


def slug(text: str, *, fallback: str = "unnamed") -> str:
    """Lowercase, dash-separated identifier fragment."""

    cleaned = _SLUG_RE.sub("-", (text or "").strip().lower()).strip("-")
    return cleaned[:80] or fallback


def human_bytes(count: int | float | None) -> str:
    if count is None:
        return "unknown"
    value = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def human_gib(count: int | float | None) -> str:
    if count is None:
        return "unknown"
    return f"{float(count) / (1024**3):.0f} GiB"


def human_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "unknown"
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m"
    if total < 86_400:
        hours, minutes = divmod(total // 60, 60)
        return f"{hours}h{minutes:02d}m"
    days, remainder = divmod(total, 86_400)
    return f"{days}d{remainder // 3600:02d}h"


def humanize_key(key: str) -> str:
    return key.replace("_", " ").replace("-", " ").strip().capitalize()


def clip(value: Any, limit: int = 80) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def boolish(raw: str) -> bool | None:
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on", "y"}:
        return True
    if lowered in {"0", "false", "no", "off", "n"}:
        return False
    return None


def to_int(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    if isinstance(raw, str):
        match = re.search(r"-?\d+", raw.replace(",", ""))
        if match:
            return int(match.group(0))
    return None


def to_float(raw: Any) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        match = re.search(r"-?\d+(?:\.\d+)?", raw)
        if match:
            return float(match.group(0))
    return None
