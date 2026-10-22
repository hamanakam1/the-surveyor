"""The network scanner, end to end, with the probes stubbed.

The parsers are tested against recorded output elsewhere. This file checks
the part that matters more: that the scanner puts the right nodes and edges
in the plat, and that it refuses to invent an identity it did not observe.
"""

from __future__ import annotations

from surveyor.config import Config
from surveyor.model import KIND_DEVICE
from surveyor.probe import Probe
from surveyor.scanners import network as scanner
from surveyor.scanners.base import ScanContext

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether f0:18:98:aa:bb:cc
\tinet 192.168.53.209 netmask 0xffffff00 broadcast 192.168.53.255
\tstatus: active
"""

ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 192.168.53.1
  interface: en0
"""

ARP = """? (192.168.53.1) at f0:18:98:11:22:33 on en0 ifscope [ethernet]
? (192.168.53.17) at 3c:22:fb:44:55:66 on en0 ifscope [ethernet]
? (192.168.53.88) at (incomplete) on en0 ifscope [ethernet]
? (192.168.53.209) at f0:18:98:aa:bb:cc on en0 ifscope [ethernet]
"""


class FakeRunner:
    """A stand-in for ``probe.run`` that answers from a table."""

    def __init__(self, table: dict[str, str]) -> None:
        self.table = table
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout: float = 8.0) -> Probe:
        vector = tuple(argv)
        self.calls.append(vector)
        command = " ".join(vector)
        # The longest matching needle wins, so a specific command can be
        # answered differently from the general one it contains.
        best: tuple[int, str] | None = None
        for needle, output in self.table.items():
            if needle in command and (best is None or len(needle) > best[0]):
                best = (len(needle), output)
        if best is not None:
            return Probe(vector, ok=True, stdout=best[1])
        return Probe(vector, ok=False, reason="not installed")


def _context(platform: str = "darwin") -> ScanContext:
    return ScanContext(config=Config(), site="edge", platform=platform)


def _run(table: dict[str, str], platform: str = "darwin"):
    runner = FakeRunner(table)
    original = scanner.run
    scanner.run = runner  # type: ignore[assignment]
    try:
        return scanner.scan_network(_context(platform)), runner
    finally:
        scanner.run = original  # type: ignore[assignment]


def test_the_gateway_becomes_an_observed_device_when_the_wire_answers():
    result, _ = _run(
        {"ifconfig": IFCONFIG, "route": ROUTE, "arp": ARP},
    )
    devices = [node for node in result.nodes if node.kind == KIND_DEVICE]
    gateway = next(node for node in devices if node.facts.get("role") == "gateway")

    # The gateway was seen on the wire, so it has a durable identity.
    assert gateway.id == "device:f0-18-98-11-22-33"
    assert gateway.facts["mac"] == "f0:18:98:11:22:33"
    assert "observed" in gateway.tags
    assert "unverified" not in gateway.tags


def test_the_network_layer_is_exactly_these_nodes():
    """The complete set, not a sample of it.

    A parser that starts reading a field the OS has just added would
    otherwise add a node nobody noticed.
    """

    result, _ = _run({"ifconfig": IFCONFIG, "route": ROUTE, "arp": ARP})
    assert {node.id for node in result.nodes} == {
        "iface:mac:en0",
        "network:192.168.53.0/24",
        "device:f0-18-98-11-22-33",
        "device:3c-22-fb-44-55-66",
    }
    assert {edge.id for edge in result.edges} == {
        "host:mac|hosts|iface:mac:en0",
        "iface:mac:en0|attaches_to|network:192.168.53.0/24",
        "host:mac|routes_via|device:f0-18-98-11-22-33",
        "device:f0-18-98-11-22-33|member_of|network:192.168.53.0/24",
        "device:3c-22-fb-44-55-66|member_of|network:192.168.53.0/24",
    }


def test_a_neighbour_becomes_a_device_on_the_subnet():
    result, _ = _run({"ifconfig": IFCONFIG, "route": ROUTE, "arp": ARP})
    peers = [
        node
        for node in result.nodes
        if node.kind == KIND_DEVICE and node.facts.get("role") != "gateway"
    ]
    assert len(peers) == 1
    peer = peers[0]
    assert peer.id == "device:3c-22-fb-44-55-66"
    assert peer.facts["address"] == "192.168.53.17"
    assert peer.facts["interface"] == "en0"

    # The peer is on the subnet, and the plat says so.
    memberships = [
        edge for edge in result.edges if edge.relation == "member_of" and edge.source == peer.id
    ]
    assert len(memberships) == 1
    assert memberships[0].target == "network:192.168.53.0/24"


def test_a_neighbour_without_a_hardware_address_is_not_invented():
    result, _ = _run({"ifconfig": IFCONFIG, "route": ROUTE, "arp": ARP})
    assert not [node for node in result.nodes if node.facts.get("address") == "192.168.53.88"]
    assert any("without a hardware address" in note for note in result.notes)


def test_the_host_does_not_become_its_own_neighbour():
    result, _ = _run({"ifconfig": IFCONFIG, "route": ROUTE, "arp": ARP})
    devices = [node for node in result.nodes if node.kind == KIND_DEVICE]
    assert not [node for node in devices if node.facts.get("address") == "192.168.53.209"]


def test_an_unverified_gateway_falls_back_to_its_address():
    """No hardware address means no durable identity, and the plat says so."""

    result, _ = _run(
        {
            "ifconfig": IFCONFIG,
            "route": ROUTE,
            "arp": "? (192.168.53.88) at (incomplete) on en0 ifscope [ethernet]\n",
        }
    )
    gateway = next(
        node for node in result.nodes if node.facts.get("role") == "gateway"
    )
    assert gateway.id == "device:192.168.53.1"
    assert "unverified" in gateway.tags


def test_no_neighbour_table_means_no_peers_not_an_error():
    result, _ = _run({"ifconfig": IFCONFIG, "route": ROUTE})
    gateway = next(
        node for node in result.nodes if node.facts.get("role") == "gateway"
    )
    assert gateway.id == "device:192.168.53.1"
    assert result.ok is True


def test_linux_reads_the_neighbour_table_too():
    addr = (
        "2: enp0s31f6    inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic enp0s31f6\n"
    )
    link = (
        "2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel "
        "state UP mode DEFAULT group default qlen 1000    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
    )
    neigh = "10.0.0.1 dev enp0s31f6 lladdr 11:22:33:44:55:66 REACHABLE\n"
    route = "default via 10.0.0.1 dev enp0s31f6 proto dhcp metric 100\n"
    result, _ = _run(
        {"ip -o addr": addr, "ip -o link": link, "ip neigh": neigh, "ip route": route},
        platform="linux",
    )
    devices = [node for node in result.nodes if node.kind == KIND_DEVICE]
    assert any(node.id == "device:11-22-33-44-55-66" for node in devices)


IFCONFIG6 = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether f0:18:98:aa:bb:cc
\tinet6 fe80::1c2b:3c4d:5e6f:7081%en0 prefixlen 64 secured scopeid 0xe
\tinet6 2001:db8:abcd::1 prefixlen 64 autoconf secured
\tinet 192.168.53.209 netmask 0xffffff00 broadcast 192.168.53.255
\tstatus: active
"""

ROUTE6 = """   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
"""


def test_an_ipv6_prefix_becomes_a_subnet():
    result, _ = _run({"ifconfig": IFCONFIG6, "route": ROUTE, "arp": ARP})
    prefixes = {
        node.id: node for node in result.nodes if node.kind == "network"
    }
    assert "network:2001:db8:abcd::/64" in prefixes
    assert prefixes["network:2001:db8:abcd::/64"].facts["family"] == "ipv6"
    assert prefixes["network:fe80::/64"].facts["scope"] == "link-local"


def test_an_ipv6_gateway_becomes_a_device():
    result, _ = _run(
        {"ifconfig": IFCONFIG6, "route": ROUTE, "route -n get -inet6": ROUTE6, "arp": ARP}
    )
    gateways = [
        node
        for node in result.nodes
        if node.kind == KIND_DEVICE and node.facts.get("family") == "ipv6"
    ]
    assert len(gateways) == 1
    assert gateways[0].facts["address"] == "fe80::1"
    assert gateways[0].facts["scope"] == "link-local"


def test_an_ipv6_only_interface_is_not_dropped():
    """It was dropped before, because the rule said "without an IPv4 address"."""

    only_v6 = """en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether f0:18:98:aa:bb:cd
\tinet6 fe80::9999:8888:7777:6666%en1 prefixlen 64 secured scopeid 0x7
\tstatus: active
"""
    result, _ = _run({"ifconfig": only_v6, "route": ROUTE, "arp": ARP})
    assert [node for node in result.nodes if node.kind == "interface"]
    assert not any("without an address" in note for note in result.notes)
