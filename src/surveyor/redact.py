"""Redaction for surveys that leave the machine.

The ledger is local, but plats get pasted into issues, commits, and chats. A
redacted survey keeps its shape and loses the identifiers: MAC addresses keep
their vendor prefix, serial numbers become digests, public addresses lose their
host bits, and names -- hostnames, container names, model names, process names
-- become stable aliases.

Private and loopback addresses are preserved on purpose -- a topology map
without them is not a topology map.

The aliases are *keyed*: the same name always produces the same alias within
one ledger, and a different one in a different ledger. An unkeyed digest of a
low-entropy value such as a hostname or a container name can be brute-forced
by hashing a word list, which would make redaction a speed bump rather than a
protection. The key lives beside the ledger it protects.

What gets masked, and what does not, is declared in :mod:`surveyor.sensitivity`
rather than guessed here, and :func:`audit` reports anything the policy did
not recognise so an operator can see the residue before publishing.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable

from .model import Edge, Node, Topology
from .sensitivity import (
    PARTIAL_KEYS,
    id_name_component,
    image_owner,
    is_sensitive,
)
from .util import sha256_hex, slug

#: A MAC address, in the colon form and the dash form.
_MAC = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", re.IGNORECASE)

#: A dotted quad.
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

#: Anything colon-separated that might be an IPv6 address. Candidates are
#: confirmed with :mod:`ipaddress`, so clock readings like ``16:04:05`` and
#: port lists like ``8080:9090`` pass through untouched.
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,})(?![0-9A-Za-z.])"
)

#: A canonical UUID.
_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)

#: A long run of hex digits, which is usually a digest of something.
_LONG_HEX = re.compile(r"\b(?![0-9a-f]{10,}\b)[0-9a-f]{16,}\b", re.IGNORECASE)

#: An email address. Nothing the scanners collect today, but a plat is a
#: document and documents get annotated.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: A home directory, which carries the operator's name.
_HOME_PATH = re.compile(r"/(?:Users|home)/([A-Za-z0-9._-]+)")

#: The boundary of a token: a name embedded in a longer word is not a match.
_TOKEN_EDGE = r"(?<![A-Za-z0-9._-])"
_TOKEN_END = r"(?![A-Za-z0-9._-])"


# --------------------------------------------------------------------------
# masking primitives
# --------------------------------------------------------------------------
def mask_mac(value: str) -> str:
    """Keep the vendor prefix; replace the host bits."""

    def replace(match: re.Match[str]) -> str:
        text = match.group(1)
        separator = "-" if "-" in text else ":"
        octets = text.lower().split(separator)
        return separator.join(octets[:3] + ["xx", "xx", "xx"])

    return _MAC.sub(replace, value)


def is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(parsed.is_global)


def mask_ip(value: str) -> str:
    """Truncate globally routable addresses; leave private ones alone."""

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(1)
        if not is_public(candidate):
            return candidate
        octets = candidate.split(".")
        return ".".join(octets[:2] + ["x", "x"])

    text = _IPV4.sub(replace, value)

    def replace_v6(match: re.Match[str]) -> str:
        candidate = match.group(1)
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if not parsed.is_global or parsed.version != 6:
            return candidate
        # Keep the routing prefix, drop the host bits.
        packed = int(parsed) >> 64 << 64
        return str(ipaddress.IPv6Address(packed))

    return _IPV6_CANDIDATE.sub(replace_v6, text)


def mask_uuid(value: str) -> str:
    return _UUID.sub("sha256:" + sha256_hex(value)[:10], value)


# --------------------------------------------------------------------------
# aliases
# --------------------------------------------------------------------------
class Aliaser:
    """A keyed, stable replacement for a name.

    The alias is derived from the *slug* of the value, so the raw name
    (``qwen3.8:32b``) and the name as it appears in a node id
    (``qwen3-8-32b``) collapse to one alias rather than two.
    """

    def __init__(self, salt: str = "") -> None:
        self.salt = salt
        self._table: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    @property
    def keyed(self) -> bool:
        return bool(self.salt)

    def alias(self, value: str) -> str:
        """Register a value and return its alias."""

        text = str(value).strip()
        if not text:
            return text
        canonical = slug(text)
        alias = "sha256:" + sha256_hex(f"{self.salt}\x00{canonical}")[:10]
        self._table.setdefault(text, alias)
        if canonical != text:
            self._table.setdefault(canonical, alias)
        self._pattern = None
        return alias

    def known(self) -> Iterable[str]:
        return self._table.keys()

    def _compile(self) -> re.Pattern[str] | None:
        if self._pattern is not None:
            return self._pattern
        if not self._table:
            return None
        # Longest first, so a longer name is never shadowed by a shorter one
        # that happens to be a prefix of it.
        alternatives = sorted(self._table, key=len, reverse=True)
        joined = "|".join(re.escape(item) for item in alternatives)
        self._pattern = re.compile(f"{_TOKEN_EDGE}({joined}){_TOKEN_END}")
        return self._pattern

    def substitute(self, text: str) -> str:
        """Replace every known name in ``text`` with its alias."""

        if not isinstance(text, str) or not text:
            return text
        pattern = self._compile()
        if pattern is None:
            return text
        return pattern.sub(lambda match: self._table.get(match.group(1), match.group(1)), text)

    def leaks(self, text: str) -> list[str]:
        """Which known names still appear in ``text``."""

        if not isinstance(text, str) or not text:
            return []
        pattern = self._compile()
        if pattern is None:
            return []
        return sorted({match.group(1) for match in pattern.finditer(text)})


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
@dataclass
class Collector:
    """Gathers the values a plat needs to stop carrying."""

    aliaser: Aliaser
    values: dict[str, set[str]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def note(self, category: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self.note(category, item)
            return
        if isinstance(value, dict):
            for item in value.values():
                self.note(category, item)
            return
        if not isinstance(value, str):
            return
        text = value.strip()
        if not text:
            return
        if text.startswith("sha256:"):
            # Already an alias. Redacting a redacted plat must not alias the
            # alias.
            return
        self.values.setdefault(category, set()).add(text)
        self.counts[category] = self.counts.get(category, 0) + 1

    def collect_node(self, node: Node) -> None:
        for key, value in node.facts.items():
            if is_sensitive(node.kind, key):
                self.note(key, value)
            if key in PARTIAL_KEYS and isinstance(value, str):
                owner = image_owner(value)
                if owner:
                    self.note("image_owner", owner)
        for key, value in node.telemetry.items():
            if is_sensitive(node.kind, key):
                self.note(key, value)
        name = id_name_component(node.id)
        if name:
            self.note(_id_category(node.id), name)
        if node.kind in {"workload", "model"} and node.label:
            self.note(_id_category(node.id) or node.kind, node.label)


def _id_category(node_id: str) -> str:
    if node_id.startswith("host:"):
        return "hostname"
    if node_id.startswith("iface:"):
        return "hostname"
    if node_id.startswith("model:"):
        return "model_name"
    if node_id.startswith("workload:"):
        return "container_name"
    return ""


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------
def _redact_string(text: str, aliaser: Aliaser) -> str:
    return aliaser.substitute(mask_uuid(mask_ip(mask_mac(text))))


def _redact_value(key: str, value: Any, aliaser: Aliaser, sensitive: bool) -> Any:
    if sensitive and isinstance(value, str) and value:
        return aliaser.alias(value)
    if sensitive and isinstance(value, (list, tuple)):
        return [_redact_value(key, item, aliaser, True) for item in value]
    if isinstance(value, str):
        return _redact_string(value, aliaser)
    if isinstance(value, list):
        return [_redact_value(key, item, aliaser, False) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(key, item, aliaser, False) for item in value)
    if isinstance(value, dict):
        return {inner: _redact_value(inner, item, aliaser, False) for inner, item in value.items()}
    return value


def _redact_image(value: Any, aliaser: Aliaser) -> Any:
    """Alias the registry owner of an image; keep the application name."""

    if not isinstance(value, str):
        return value
    owner = image_owner(value)
    if not owner:
        return _redact_string(value, aliaser)
    alias = aliaser.alias(owner)
    return _redact_string(value, aliaser).replace(owner, alias)


def redact_topology(topology: Topology, *, salt: str = "") -> Topology:
    """Return a copy of the survey with identifying values masked."""

    aliaser = Aliaser(salt)
    collector = Collector(aliaser=aliaser)
    for node in topology.nodes.values():
        collector.collect_node(node)
    for edge in topology.edges:
        for key, value in edge.facts.items():
            if key in {"workload", "container"}:
                collector.note("container_name", value)

    # Register every collected name before anything is rewritten, so that a
    # name found in a fact also disappears from the ids and labels.
    for category, values in collector.values.items():
        for value in values:
            aliaser.alias(value)

    redacted = Topology(
        site=topology.site,
        generated_at=topology.generated_at,
        observations={
            **_redact_observations(topology.observations, aliaser),
            "redacted": True,
            "redaction_policy": (
                "names aliased with a keyed digest, macs masked, "
                "public addresses truncated, serials and ssids aliased"
            ),
            "redaction_keyed": aliaser.keyed,
        },
        schema_version=topology.schema_version,
    )

    for node in topology.nodes.values():
        redacted.add(_redact_node(node, aliaser))

    for edge in topology.edges:
        source = aliaser.substitute(edge.source)
        target = aliaser.substitute(edge.target)
        facts = {
            key: (
                aliaser.alias(value)
                if key in {"workload", "container"} and isinstance(value, str) and value
                else _redact_value(key, value, aliaser, False)
            )
            for key, value in edge.facts.items()
        }
        if source in redacted.nodes and target in redacted.nodes:
            redacted.connect(Edge(source, edge.relation, target, facts))
    return redacted


def _redact_observations(observations: dict[str, Any], aliaser: Aliaser) -> dict[str, Any]:
    """Redact every string in the observation record, not just the notes."""

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return _redact_string(value, aliaser)
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, tuple):
            return tuple(walk(item) for item in value)
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        return value

    return {key: walk(value) for key, value in observations.items()}


def _redact_node(node: Node, aliaser: Aliaser) -> Node:
    facts: dict[str, Any] = {}
    for key, value in node.facts.items():
        if key in PARTIAL_KEYS:
            facts[key] = _redact_image(value, aliaser)
            continue
        sensitive = is_sensitive(node.kind, key)
        facts[key] = _redact_value(key, value, aliaser, sensitive)
    telemetry = {
        key: _redact_value(key, value, aliaser, is_sensitive(node.kind, key))
        for key, value in node.telemetry.items()
    }
    return Node(
        id=aliaser.substitute(node.id),
        kind=node.kind,
        label=_redact_string(node.label, aliaser),
        layer=node.layer,
        facts=facts,
        telemetry=telemetry,
        tags=node.tags,
        source=node.source,
    )


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
@dataclass
class Finding:
    """One thing the redaction policy did not recognise."""

    kind: str
    value: str
    where: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "where": self.where}


def _strings(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


def _shape_findings(path: str, text: str) -> list[Finding]:
    """Identifiers that survived because nothing declared them."""

    found: list[Finding] = []
    for match in _MAC.finditer(text):
        found.append(Finding("mac", match.group(1), path))
    for match in _IPV4.finditer(text):
        candidate = match.group(1)
        if is_public(candidate):
            found.append(Finding("public-ipv4", candidate, path))
    for match in _IPV6_CANDIDATE.finditer(text):
        candidate = match.group(1)
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == 6 and parsed.is_global:
            found.append(Finding("public-ipv6", candidate, path))
    for match in _UUID.finditer(text):
        found.append(Finding("uuid", match.group(0), path))
    for match in _LONG_HEX.finditer(text):
        found.append(Finding("long-hex", match.group(0), path))
    for match in _EMAIL.finditer(text):
        found.append(Finding("email", match.group(0), path))
    for match in _HOME_PATH.finditer(text):
        found.append(Finding("home-path", match.group(1), path))
    return found


def audit(topology: Topology, redacted: Topology, aliaser: Aliaser) -> list[Finding]:
    """Report every identifier that survived redaction.

    Two kinds of finding: a name the policy *knows* about and failed to
    remove, and a value that merely *looks* like an identifier. The first is
    a bug. The second is a question for the operator.
    """

    findings: list[Finding] = []
    document = redacted.to_dict()
    for path, text in _strings(document, "plat"):
        for leak in aliaser.leaks(text):
            findings.append(Finding("known-identifier", leak, path))
        findings.extend(_shape_findings(path, text))
    return findings


def masked_summary(topology: Topology, aliaser: Aliaser) -> dict[str, int]:
    """What was masked, by category."""

    summary: dict[str, int] = {}
    for category, values in _collected(topology).items():
        summary[category] = len(values)
    return summary


def _collected(topology: Topology) -> dict[str, set[str]]:
    collector = Collector(aliaser=Aliaser())
    for node in topology.nodes.values():
        collector.collect_node(node)
    return collector.values


def new_salt() -> str:
    """A fresh redaction key."""

    return secrets.token_hex(32)
