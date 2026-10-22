"""Redaction for surveys that leave the machine.

The ledger is local, but plats get pasted into issues, commits, and chats. A
redacted survey keeps its shape and loses the identifiers: MAC addresses keep
their vendor prefix, serial numbers become digests, public addresses lose their
host bits, and Wi-Fi SSIDs are replaced with stable aliases.

Private and loopback addresses are preserved on purpose -- a topology map
without them is not a topology map.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .model import Node, Topology
from .util import sha256_hex

_MAC = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SERIAL_KEYS = frozenset(
    {
        "serial",
        "serial_number",
        "hardware_uuid",
        "machine_id",
        "board_id",
        "uuid",
        "wifi_ssid",
        "ssid",
    }
)


def mask_mac(value: str) -> str:
    match = _MAC.search(value)
    if not match:
        return value
    octets = match.group(1).lower().split(":")
    masked = ":".join(octets[:3] + ["xx", "xx", "xx"])
    return value[: match.start(1)] + masked + value[match.end(1) :]


def is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(parsed.is_global)


def mask_ip(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(1)
        if not is_public(candidate):
            return candidate
        octets = candidate.split(".")
        return ".".join(octets[:2] + ["x", "x"])

    return _IPV4.sub(replace, value)


def alias_secret(value: str) -> str:
    return "sha256:" + sha256_hex(value.strip())[:10]


def _redact_value(key: str, value: Any) -> Any:
    if key in _SERIAL_KEYS and isinstance(value, str) and value:
        return alias_secret(value)
    if isinstance(value, str):
        return mask_ip(mask_mac(value))
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(key, item) for item in value)
    if isinstance(value, dict):
        return {inner: _redact_value(inner, item) for inner, item in value.items()}
    return value


def redact_node(node: Node) -> Node:
    return Node(
        id=node.id,
        kind=node.kind,
        label=mask_ip(mask_mac(node.label)),
        layer=node.layer,
        facts={key: _redact_value(key, value) for key, value in node.facts.items()},
        telemetry={key: _redact_value(key, value) for key, value in node.telemetry.items()},
        tags=node.tags,
        source=node.source,
    )


def _mask_text(value: Any) -> Any:
    """Mask identifiers inside free-form observation notes."""

    if isinstance(value, str):
        return mask_ip(mask_mac(value))
    if isinstance(value, list):
        return [_mask_text(item) for item in value]
    if isinstance(value, dict):
        return {key: _mask_text(item) for key, item in value.items()}
    return value


def redact_topology(topology: Topology) -> Topology:
    """Return a copy of the survey with identifying values masked."""

    redacted = Topology(
        site=topology.site,
        generated_at=topology.generated_at,
        observations={
            **topology.observations,
            "warnings": _mask_text(topology.observations.get("warnings", [])),
            "conflicts": _mask_text(topology.observations.get("conflicts", [])),
            "redacted": True,
            "redaction_policy": "macs masked, serials hashed, public addresses truncated, ssids aliased",
        },
        schema_version=topology.schema_version,
    )
    for node in topology.nodes.values():
        redacted.nodes[node.id] = redact_node(node)
    redacted.edges = list(topology.edges)
    return redacted
