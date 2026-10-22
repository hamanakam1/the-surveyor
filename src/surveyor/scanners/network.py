"""Network scanner: interfaces, addresses, subnets, and the default gateway.

The scanner is conservative by design. Loopback, tunnels, and other synthetic
interfaces are omitted unless explicitly requested, because a macOS box can
report thirty interfaces and only two of them are places packets actually go.

Parsers are pure functions over command output so they can be tested against
recorded fixtures without touching the host.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any

from ..identity import host_id as local_host_id
from ..identity import hostname
from ..model import (
    KIND_DEVICE,
    KIND_INTERFACE,
    KIND_NETWORK,
    LAYER_NETWORK,
    REL_ATTACHES_TO,
    REL_HOSTS,
    REL_MEMBER_OF,
    REL_ROUTES_VIA,
    Edge,
    Node,
)
from ..probe import ProbeLog, run
from ..util import slug
from .base import ScanContext, ScanResult, register

#: Interface prefixes that represent software, not cabling.
VIRTUAL_PREFIXES = (
    "lo",
    "gif",
    "stf",
    "utun",
    "awdl",
    "llw",
    "anpi",
    "bridge",
    "ap",
    "nan",
    "p2p",
    "vmnet",
    "veth",
    "docker",
    "br-",
    "virbr",
    "tun",
    "tap",
    "tailscale",
    "zt",
    "wg",
    "ipsec",
    "ppp",
)

PHYSICAL_PREFIXES = ("en", "eth", "wlan", "wl", "usb", "rmnet", "ww", "em", "eno", "enp", "ens")

_IFCONFIG_HEADER = re.compile(
    r"^(?P<name>[a-z0-9_.-]+):\s+flags=[0-9a-f]+<(?P<flags>[^>]*)>\s+mtu\s+(?P<mtu>\d+)",
    re.IGNORECASE,
)
_IFCONFIG_INET = re.compile(
    r"^\s+inet\s+(?P<addr>\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+(?P<mask>0x[0-9a-f]+|\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_IFCONFIG_INET6 = re.compile(
    r"^\s+inet6\s+(?P<addr>[0-9a-f:]+)(?:%\S+)?\s+prefixlen\s+(?P<prefix>\d+)",
    re.IGNORECASE,
)
_IFCONFIG_MAC = re.compile(r"^\s+ether\s+(?P<mac>[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})", re.IGNORECASE)
_IFCONFIG_STATUS = re.compile(r"^\s+status:\s+(?P<status>\w+)", re.IGNORECASE)
_IP_ADDR = re.compile(r"^\d+:\s+(?P<name>[^:@\s]+)(?:@\S+)?\s+(?P<family>inet6?)\s+(?P<addr>\S+)")
_IP_LINK = re.compile(
    r"^\d+:\s+(?P<name>[^:@\s]+)(?:@\S+)?:\s+<(?P<flags>[^>]*)>.*?mtu\s+(?P<mtu>\d+)(?P<rest>.*)$"
)
_IP_MAC = re.compile(r"link/ether\s+(?P<mac>[0-9a-f:]{17})", re.IGNORECASE)
_IP_STATE = re.compile(r"\bstate\s+(?P<state>[A-Z]+)")
_ROUTE_GATEWAY = re.compile(r"^\s*gateway:\s*(?P<gateway>\d{1,3}(?:\.\d{1,3}){3})", re.MULTILINE)
_ROUTE_GATEWAY6 = re.compile(r"^\s*gateway:\s*(?P<gateway>[0-9a-f:]+)(?:%\S+)?\s*$", re.MULTILINE | re.IGNORECASE)
_ROUTE_INTERFACE = re.compile(r"^\s*interface:\s*(?P<iface>\S+)", re.MULTILINE)
_DEFAULT_ROUTE = re.compile(
    r"default\s+via\s+(?P<gateway>\d{1,3}(?:\.\d{1,3}){3})(?:\s+dev\s+(?P<iface>\S+))?"
)
_DEFAULT_ROUTE6 = re.compile(
    r"^default\s+via\s+(?P<gateway>[0-9a-f:]+)(?:%\S+)?(?:\s+dev\s+(?P<iface>\S+))?",
    re.MULTILINE | re.IGNORECASE,
)
_HARDWARE_PORT = re.compile(r"Hardware Port:\s*(?P<port>.+?)\s*\nDevice:\s*(?P<device>\S+)")
_WIFI_NETWORK = re.compile(r"Current Wi-Fi Network:\s*(?P<ssid>.+)")

#: macOS ``arp -an``: "? (192.168.53.1) at f0:18:98:aa:bb:cc on en0 ifscope [ethernet]"
_ARP_AN = re.compile(
    r"^\?\s+\((?P<addr>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+on\s+(?P<iface>\S+)",
    re.IGNORECASE,
)

#: macOS ``arp -an`` for a neighbour that has not answered yet.
_ARP_INCOMPLETE = re.compile(
    r"^\?\s+\((?P<addr>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+\(incomplete\)", re.IGNORECASE
)

#: Linux ``ip neigh show``: "192.168.53.1 dev en0 lladdr f0:18:98:aa:bb:cc REACHABLE"
_IP_NEIGH = re.compile(
    r"^(?P<addr>\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+(?P<iface>\S+)"
    r"(?:\s+lladdr\s+(?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5}))?"
    r"(?:\s+(?P<state>[A-Z]+))?",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Peer:
    """A neighbour seen in the system's address-resolution table."""

    address: str
    mac: str = ""
    interface: str = ""
    state: str = ""

    @property
    def identified(self) -> bool:
        """Whether this peer has a durable identity.

        An address is not an identity: a DHCP lease moves, and the device
        does not. A hardware address survives the move.
        """

        return bool(self.mac)


@dataclass(slots=True)
class Interface:
    """One observed network interface."""

    name: str
    mtu: int = 0
    mac: str = ""
    state: str = ""
    up: bool = False
    ipv4: list[tuple[str, int]] = field(default_factory=list)
    ipv6: list[tuple[str, int]] = field(default_factory=list)
    kind: str = "unknown"

    @property
    def primary_address(self) -> str:
        return self.ipv4[0][0] if self.ipv4 else ""

    @property
    def addressed(self) -> bool:
        """Whether this interface has an address of any family."""

        return bool(self.ipv4 or self.ipv6)

    def to_facts(self) -> dict[str, Any]:
        facts: dict[str, Any] = {"name": self.name, "kind": self.kind}
        if self.mtu:
            facts["mtu"] = self.mtu
        if self.mac:
            facts["mac"] = self.mac.lower()
        if self.ipv4:
            facts["ipv4"] = [f"{addr}/{prefix}" for addr, prefix in self.ipv4]
            facts["address"] = self.primary_address
        if self.ipv6:
            facts["ipv6"] = [f"{addr}/{prefix}" for addr, prefix in self.ipv6]
        return facts


def _mask_to_prefix(mask: str) -> int:
    if mask.startswith("0x"):
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{int(mask, 16)}").prefixlen
        except ValueError:
            return 24
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 24


def parse_ifconfig(text: str) -> list[Interface]:
    """Parse BSD/macOS ``ifconfig -a`` output."""

    interfaces: list[Interface] = []
    current: Interface | None = None
    for raw in text.splitlines():
        header = _IFCONFIG_HEADER.match(raw)
        if header:
            current = Interface(
                name=header.group("name"),
                mtu=int(header.group("mtu")),
                up="UP" in header.group("flags").split(","),
            )
            interfaces.append(current)
            continue
        if current is None:
            continue
        mac = _IFCONFIG_MAC.match(raw)
        if mac:
            current.mac = mac.group("mac")
            continue
        inet = _IFCONFIG_INET.match(raw)
        if inet:
            current.ipv4.append(
                (inet.group("addr"), _mask_to_prefix(inet.group("mask")))
            )
            continue
        inet6 = _IFCONFIG_INET6.match(raw)
        if inet6:
            address = inet6.group("addr")
            try:
                parsed = ipaddress.IPv6Address(address)
            except ValueError:
                continue
            current.ipv6.append((str(parsed), int(inet6.group("prefix"))))
            continue
        status = _IFCONFIG_STATUS.match(raw)
        if status:
            current.state = status.group("status").lower()
    return interfaces


def parse_ip_addr(addr_text: str, link_text: str = "") -> list[Interface]:
    """Parse Linux ``ip -o addr`` (optionally enriched by ``ip -o link``)."""

    found: dict[str, Interface] = {}
    for raw in link_text.splitlines():
        link = _IP_LINK.match(raw)
        if not link:
            continue
        name = link.group("name")
        iface = found.setdefault(name, Interface(name=name))
        iface.mtu = int(link.group("mtu"))
        iface.up = "UP" in link.group("flags").split(",")
        mac = _IP_MAC.search(link.group("rest") or "")
        if mac:
            iface.mac = mac.group("mac").lower()
        state = _IP_STATE.search(link.group("rest") or "")
        if state:
            iface.state = state.group("state").lower()

    for raw in addr_text.splitlines():
        match = _IP_ADDR.match(raw)
        if not match:
            continue
        name = match.group("name")
        iface = found.setdefault(name, Interface(name=name))
        address = match.group("addr")
        if match.group("family") == "inet":
            try:
                parsed4 = ipaddress.IPv4Interface(address)
            except ValueError:
                continue
            iface.ipv4.append((str(parsed4.ip), parsed4.network.prefixlen))
            continue
        # IPv6. The scope suffix (``%en0``) is a local routing detail, not
        # part of the address.
        bare = address.split("%", 1)[0]
        try:
            parsed6 = ipaddress.IPv6Interface(bare)
        except ValueError:
            continue
        iface.ipv6.append((str(parsed6.ip), parsed6.network.prefixlen))
    return list(found.values())


def parse_hardware_ports(text: str) -> dict[str, str]:
    """Map device name -> friendly hardware port name on macOS."""

    mapping: dict[str, str] = {}
    for match in _HARDWARE_PORT.finditer(text):
        mapping[match.group("device").strip()] = match.group("port").strip()
    return mapping


def parse_arp_an(text: str) -> list[Peer]:
    """Parse macOS ``arp -an`` output."""

    peers: list[Peer] = []
    for raw in text.splitlines():
        match = _ARP_AN.match(raw)
        if match:
            peers.append(
                Peer(
                    address=match.group("addr"),
                    mac=match.group("mac").lower(),
                    interface=match.group("iface"),
                )
            )
            continue
        incomplete = _ARP_INCOMPLETE.match(raw)
        if incomplete:
            peers.append(Peer(address=incomplete.group("addr")))
    return peers


def parse_ip_neigh(text: str) -> list[Peer]:
    """Parse Linux ``ip neigh show`` output."""

    peers: list[Peer] = []
    for raw in text.splitlines():
        match = _IP_NEIGH.match(raw)
        if not match:
            continue
        peers.append(
            Peer(
                address=match.group("addr"),
                mac=(match.group("mac") or "").lower(),
                interface=match.group("iface"),
                state=(match.group("state") or "").upper(),
            )
        )
    return peers


def classify(name: str, port_name: str = "") -> str:
    lowered = name.lower()
    port = port_name.lower()
    if lowered.startswith("lo"):
        return "loopback"
    if "wi-fi" in port or "airport" in port or lowered.startswith(("wl", "wlan")):
        return "wifi"
    if lowered.startswith(VIRTUAL_PREFIXES):
        return "virtual"
    if "thunderbolt" in port:
        return "thunderbolt"
    if "ethernet" in port or lowered.startswith(("eth", "en")):
        return "ethernet"
    if lowered.startswith(("usb", "ww", "rmnet")):
        return "cellular" if lowered.startswith(("ww", "rmnet")) else "usb"
    return "unknown"


@dataclass(slots=True)
class Route:
    """A default route, of either family."""

    family: str
    gateway: str
    interface: str = ""


def _default_routes(ctx: ScanContext, log: ProbeLog) -> list[Route]:
    """The host's default routes, for both address families.

    A dual-stacked box has two of them, and a map that only shows one is
    showing half of the story.
    """

    routes: list[Route] = []
    if ctx.platform == "darwin":
        probe = log.add(run(["route", "-n", "get", "default"], timeout=ctx.timeout))
        if probe.ok:
            gateway = _ROUTE_GATEWAY.search(probe.stdout)
            iface = _ROUTE_INTERFACE.search(probe.stdout)
            if gateway:
                routes.append(
                    Route(
                        family="ipv4",
                        gateway=gateway.group("gateway"),
                        interface=iface.group("iface") if iface else "",
                    )
                )
        probe6 = log.add(run(["route", "-n", "get", "-inet6", "default"], timeout=ctx.timeout))
        if probe6.ok:
            gateway6 = _ROUTE_GATEWAY6.search(probe6.stdout)
            iface6 = _ROUTE_INTERFACE.search(probe6.stdout)
            if gateway6:
                routes.append(
                    Route(
                        family="ipv6",
                        gateway=gateway6.group("gateway"),
                        interface=iface6.group("iface") if iface6 else "",
                    )
                )
        return routes

    if ctx.platform.startswith("linux"):
        probe = log.add(run(["ip", "route", "show", "default"], timeout=ctx.timeout))
        if probe.ok:
            match = _DEFAULT_ROUTE.search(probe.stdout)
            if match:
                routes.append(
                    Route(
                        family="ipv4",
                        gateway=match.group("gateway"),
                        interface=match.group("iface") or "",
                    )
                )
        probe6 = log.add(run(["ip", "-6", "route", "show", "default"], timeout=ctx.timeout))
        if probe6.ok:
            match6 = _DEFAULT_ROUTE6.search(probe6.stdout)
            if match6:
                routes.append(
                    Route(
                        family="ipv6",
                        gateway=match6.group("gateway"),
                        interface=match6.group("iface") or "",
                    )
                )
    return routes


def _collect(ctx: ScanContext, log: ProbeLog) -> tuple[list[Interface], dict[str, str]]:
    if ctx.platform == "darwin":
        ifconfig = log.add(run(["ifconfig", "-a"], timeout=ctx.timeout))
        interfaces = parse_ifconfig(ifconfig.stdout) if ifconfig.ok else []
        ports: dict[str, str] = {}
        netsetup = log.add(run(["networksetup", "-listallhardwareports"], timeout=ctx.timeout))
        if netsetup.ok:
            ports = parse_hardware_ports(netsetup.stdout)
        return interfaces, ports

    if ctx.platform.startswith("linux"):
        addr = log.add(run(["ip", "-o", "addr", "show"], timeout=ctx.timeout))
        link = log.add(run(["ip", "-o", "link", "show"], timeout=ctx.timeout))
        if addr.ok:
            return parse_ip_addr(addr.stdout, link.stdout if link.ok else ""), {}
        if link.ok:
            return parse_ip_addr("", link.stdout), {}

    # Last resort: names only. Better a bare interface list than silence.
    try:
        return [Interface(name=name) for _, name in socket.if_nameindex()], {}
    except OSError:  # pragma: no cover - defensive
        return [], {}


def _ipv6_scope(address: str) -> str:
    """The scope of an IPv6 address: link, local, or global.

    A link-local address is not a routable identity, and a plat that calls
    one global is lying about the shape of the network.
    """

    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError:
        return "unknown"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_private:
        return "local"
    if parsed.is_multicast:
        return "multicast"
    return "global"


def _device_id(mac: str) -> str:
    """A device's durable identity: its hardware address.

    An address is not an identity. A DHCP lease moves and the device does
    not, so a node named after its IP churns every time the lease renews.
    """

    return f"device:{mac.lower().replace(':', '-')}"


def _neighbours(ctx: ScanContext, log: ProbeLog) -> list[Peer]:
    """Read the system's address-resolution table.

    This is the only place the Surveyor can learn that something else is on
    the wire. It is also the only place a device's durable identity comes
    from.
    """

    if ctx.platform == "darwin":
        probe = log.add(run(["arp", "-an"], timeout=ctx.timeout))
        return parse_arp_an(probe.stdout) if probe.ok else []

    if ctx.platform.startswith("linux"):
        probe = log.add(run(["ip", "neigh", "show"], timeout=ctx.timeout))
        return parse_ip_neigh(probe.stdout) if probe.ok else []

    return []


def _wifi_ssid(ctx: ScanContext, device: str, log: ProbeLog) -> str:
    if ctx.platform != "darwin" or not device:
        return ""
    probe = log.add(run(["networksetup", "-getairportnetwork", device], timeout=ctx.timeout))
    if not probe.ok:
        return ""
    match = _WIFI_NETWORK.search(probe.stdout)
    return match.group("ssid").strip() if match else ""


@register(
    "network",
    LAYER_NETWORK,
    "Interfaces, IPv4 subnets, the default gateway, and neighbours on the wire",
)
def scan_network(ctx: ScanContext) -> ScanResult:
    result = ScanResult(scanner="network", layer=LAYER_NETWORK)
    log = ProbeLog()
    interfaces, ports = _collect(ctx, log)
    routes = _default_routes(ctx, log)
    gateway_route = next((route for route in routes if route.family == "ipv4"), None)
    gateway = gateway_route.gateway if gateway_route else ""
    gateway_iface = gateway_route.interface if gateway_route else ""
    host = local_host_id()

    if not interfaces:
        result.warn("no interfaces could be enumerated")
        return result

    omitted = 0
    subnets: list[tuple[Any, str]] = []
    for iface in interfaces:
        iface.kind = classify(iface.name, ports.get(iface.name, ""))
        if iface.kind == "loopback" and not ctx.config.include_loopback:
            continue
        if iface.kind == "virtual" and not ctx.config.include_virtual_interfaces:
            continue
        if not iface.addressed:
            # A port with no address is cabling, not topology. Say how many
            # were skipped rather than silently shrinking the map.
            omitted += 1
            continue

        is_primary = iface.name == gateway_iface
        facts = iface.to_facts()
        if is_primary:
            facts["default_route"] = True
        if iface.state:
            facts["link_state"] = iface.state
        if iface.kind == "wifi":
            ssid = _wifi_ssid(ctx, iface.name, log)
            if ssid:
                facts["wifi_ssid"] = ssid

        node_id = f"iface:{slug(hostname())}:{slug(iface.name)}"
        result.nodes.append(
            Node(
                id=node_id,
                kind=KIND_INTERFACE,
                label=f"{iface.name} ({iface.kind})",
                facts=facts,
                telemetry={"up": iface.up},
                tags=(iface.kind, "primary" if is_primary else "secondary"),
                source="network",
            )
        )
        result.edges.append(Edge(host, REL_HOSTS, node_id, {"role": "interface"}))

        for address, prefix in iface.ipv4:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.prefixlen >= 32:
                continue
            network_id = f"network:{network.with_prefixlen}"
            result.nodes.append(
                Node(
                    id=network_id,
                    kind=KIND_NETWORK,
                    label=network.with_prefixlen,
                    facts={
                        "cidr": network.with_prefixlen,
                        "family": "ipv4",
                        "private": network.is_private,
                        "size": network.num_addresses,
                    },
                    tags=("subnet", "private" if network.is_private else "public"),
                    source="network",
                )
            )
            result.edges.append(Edge(node_id, REL_ATTACHES_TO, network_id, {"address": address}))
            subnets.append((network, network_id))

        for address, prefix in iface.ipv6:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.prefixlen >= 128:
                continue
            network_id = f"network:{network.with_prefixlen}"
            result.nodes.append(
                Node(
                    id=network_id,
                    kind=KIND_NETWORK,
                    label=network.with_prefixlen,
                    facts={
                        "cidr": network.with_prefixlen,
                        "family": "ipv6",
                        "private": network.is_private,
                        "size": network.num_addresses,
                        "scope": _ipv6_scope(address),
                    },
                    tags=(
                        "subnet",
                        "private" if network.is_private else "public",
                        _ipv6_scope(address),
                    ),
                    source="network",
                )
            )
            result.edges.append(Edge(node_id, REL_ATTACHES_TO, network_id, {"address": address}))
            subnets.append((network, network_id))

    peers = _neighbours(ctx, log)
    own_macs = {iface.mac.lower() for iface in interfaces if iface.mac}
    own_addresses = {address for iface in interfaces for address, _ in iface.ipv4}

    if gateway:
        peer = next((item for item in peers if item.address == gateway), None)
        if peer is not None and peer.identified:
            # The gateway was seen on the wire, so it has a durable identity
            # and it is no longer a guess.
            gateway_id = _device_id(peer.mac)
            gateway_facts = {"role": "gateway", "address": gateway, "mac": peer.mac}
            gateway_tags = ("gateway", "observed")
        else:
            gateway_id = f"device:{gateway}"
            gateway_facts = {"role": "gateway", "address": gateway}
            gateway_tags = ("gateway", "unverified")
        result.nodes.append(
            Node(
                id=gateway_id,
                kind=KIND_DEVICE,
                label=f"gateway {gateway}",
                facts=gateway_facts,
                tags=gateway_tags,
                source="network",
            )
        )
        result.edges.append(Edge(host, REL_ROUTES_VIA, gateway_id, {"role": "default"}))

    # The IPv6 default route, if the host has one. A dual-stacked box has
    # two gateways, and a map that shows one of them is showing half.
    for route in routes:
        if route.family != "ipv6" or not route.gateway:
            continue
        gateway_id = f"device:{route.gateway}"
        result.nodes.append(
            Node(
                id=gateway_id,
                kind=KIND_DEVICE,
                label=f"gateway {route.gateway}",
                facts={
                    "role": "gateway",
                    "address": route.gateway,
                    "family": "ipv6",
                    "scope": _ipv6_scope(route.gateway),
                },
                tags=("gateway", "unverified"),
                source="network",
            )
        )
        result.edges.append(
            Edge(host, REL_ROUTES_VIA, gateway_id, {"role": "default", "family": "ipv6"})
        )

    unidentified = 0
    for peer in peers:
        if peer.address == gateway:
            continue
        if peer.address in own_addresses:
            continue
        if not peer.identified:
            # No hardware address means no durable identity, and a node whose
            # id is its address churns every time a lease moves.
            unidentified += 1
            continue
        if peer.mac in own_macs:
            continue
        node_id = _device_id(peer.mac)
        peer_facts: dict[str, Any] = {"address": peer.address, "mac": peer.mac}
        if peer.interface:
            peer_facts["interface"] = peer.interface
        result.nodes.append(
            Node(
                id=node_id,
                kind=KIND_DEVICE,
                label=peer.address,
                facts=peer_facts,
                telemetry={"state": peer.state} if peer.state else {},
                tags=("peer", "observed"),
                source="network",
            )
        )
        subnet_id = ""
        for network, candidate in subnets:
            try:
                if ipaddress.ip_address(peer.address) in network:
                    subnet_id = candidate
                    break
            except ValueError:
                continue
        if subnet_id:
            result.edges.append(Edge(node_id, REL_MEMBER_OF, subnet_id, {"address": peer.address}))

    if unidentified:
        result.warn(
            f"{unidentified} neighbour(s) without a hardware address omitted; "
            "an address is not an identity"
        )
    if omitted:
        result.warn(f"{omitted} interface(s) without an address omitted from the plat")
    for note in log.notes():
        result.warn(note)
    if not any(node.kind == KIND_INTERFACE for node in result.nodes):
        result.warn("only virtual interfaces were visible; physical cabling not observed")
    return result
