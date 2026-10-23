"""The inventory of what in a plat identifies the machine it came from.

Redaction is only as good as its inventory of identifiers. This module *is*
that inventory: a declaration of which fact keys hold identifiers, and which
node id components are names rather than numbers.

Keeping the inventory in one reviewable place, rather than scattered through
the redactor, is deliberate. A scanner that starts emitting a new kind of
identifier adds a line here, and the audit command then proves that the line
is doing its job. The alternative -- a redactor that guesses -- produced a
``--redact`` flag that advertised safety it did not have.

Three things are deliberately *not* identifiers, and are kept in the clear:

* **Hardware model and CPU model.** ``Mac15,8`` and ``Apple M3 Max`` describe
  the class of machine, not the machine. A map that cannot say what kind of
  box it is describing is not a map.
* **Private, loopback and link-local addresses.** A topology without them is
  a mood board. Public addresses are truncated instead.
* **Ports, versions, counts, roles and tags.** These are the shape.
"""

from __future__ import annotations

import re

#: Only the exact short digest emitted by the redactor is an existing alias.
_ALIAS = re.compile(r"sha256:[0-9a-f]{10}")

#: Fact and telemetry keys whose value identifies the thing it describes,
#: whatever kind of node the value sits on.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        # -- host identity -------------------------------------------------
        "serial",
        "serial_number",
        "hardware_uuid",
        "machine_id",
        "board_id",
        "uuid",
        # -- network identity ----------------------------------------------
        "wifi_ssid",
        "ssid",
        # -- workload identity ---------------------------------------------
        "container_id",
        "container_name",
        "compose_project",
        "compose_service",
        # -- model identity -------------------------------------------------
        "digest",
        # -- running processes ---------------------------------------------
        "processes",
    }
)

#: Keys that are identifiers only on particular kinds of node, because the
#: same key means different things on different kinds. ``name`` is the reason
#: this table exists: it is an interface name on an interface, a model name on
#: a model, and nothing at all on anything else.
SENSITIVE_KEYS_BY_KIND: dict[str, frozenset[str]] = {
    "host": frozenset({"hostname"}),
    "model": frozenset({"name"}),
    "workload": frozenset({"models"}),
    "service": frozenset({"workload"}),
    # A bind mount's source is a path on the operator's own disk, often
    # under their home directory.
    "volume": frozenset({"host_path"}),
}

#: Keys whose value names a *part* of a longer string, and so must have that
#: part replaced rather than the whole value.
PARTIAL_KEYS: frozenset[str] = frozenset({"image"})


def is_sensitive(kind: str, key: str) -> bool:
    """Whether ``key`` on a node of ``kind`` holds an identifier."""

    if key in SENSITIVE_KEYS:
        return True
    return key in SENSITIVE_KEYS_BY_KIND.get(kind, frozenset())


def is_alias(value: str) -> bool:
    """Whether a complete value has the redactor's generated alias shape."""

    return _ALIAS.fullmatch(value) is not None


def id_name_component(node_id: str) -> str:
    """The name-bearing component of a node id, if it has one.

    The OET identity conventions are the authority here, and they are simple:
    a host is named by its hostname, an interface by its host, a container by
    its container name, a model by its model name, and a service by a port
    number -- which is not a name.
    """

    parts = node_id.split(":")
    name_index = 2 if node_id.startswith("workload:") else 1
    if is_alias(":".join(parts[name_index:name_index + 2])):
        # Already an alias; there is no name left in this id.
        return ""
    if node_id.startswith("host:") and len(parts) >= 2:
        return parts[1]
    if node_id.startswith("iface:") and len(parts) >= 3:
        return parts[1]
    if node_id.startswith("model:") and len(parts) >= 2:
        return parts[1]
    if node_id.startswith("workload:") and len(parts) >= 3:
        return parts[2]
    if node_id.startswith("device:") and len(parts) >= 2:
        # A device is named by its hardware address, which is an identifier
        # in its own right. Aliasing it -- rather than masking it to its
        # vendor prefix -- keeps the peers of one machine distinct from
        # each other after redaction.
        return parts[1]
    return ""


def image_owner(image: str) -> str:
    """The registry-owner segment of a container image, if it has one.

    ``nginx:1.25`` has no owner and is not identifying. ``ghcr.io/acme/pay``
    has one, and ``acme`` is exactly the kind of thing a redacted plat should
    not carry. The application name after it is kept: it is shape.
    """

    if "/" not in image:
        return ""
    head, _, _tail = image.partition("/")
    if "." in head or ":" in head or head == "localhost":
        # The first segment is a registry host, not an owner.
        remainder = image[len(head) + 1 :]
        if "/" not in remainder:
            return ""
        return remainder.split("/", 1)[0]
    return head
