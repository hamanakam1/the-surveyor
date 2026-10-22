from __future__ import annotations

from surveyor.scanners.host import parse_df
from surveyor.scanners.network import (
    classify,
    parse_arp_an,
    parse_hardware_ports,
    parse_ifconfig,
    parse_ip_addr,
    parse_ip_neigh,
)
from surveyor.scanners.power import _parse_ioreg_battery, _parse_pmset_batt
from surveyor.scanners.workloads import _bind_of, _parse_labels, _published_ports

DF = """Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   971350180  13340060  10525016    56%    /
devfs                  207       207         0   100%    /dev
/dev/disk3s5     971350180 886325376  10525016    99%    /System/Volumes/Data
map auto_home            0         0         0   100%    /System/Volumes/Data/home
/dev/disk4s1        634756    631956      2800   100%    /Volumes/Kiro CLI
"""


def test_parse_df_reads_the_real_filesystems():
    filesystems = parse_df(DF)
    # devfs and auto_home are not storage.
    assert len(filesystems) == 3
    root = filesystems[0]
    assert root.device == "/dev/disk3s1s1"
    assert root.mount == "/"
    assert root.total_bytes == 971350180 * 1024
    assert root.percent == 56


def test_parse_df_keeps_a_mount_point_with_spaces():
    filesystems = parse_df(DF)
    assert any(item.mount == "/Volumes/Kiro CLI" for item in filesystems)


def test_parse_df_of_nothing_is_nothing():
    assert parse_df("") == []
    assert parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\n") == []

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO>
\tether f0:18:98:aa:bb:cc
\tinet6 fe80::1c2b:3c4d:5e6f:7081%en0 prefixlen 64 secured scopeid 0xe
\tinet 192.168.53.241 netmask 0xffffff00 broadcast 192.168.53.255
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:33:44:55
\tstatus: inactive
"""

ARP_AN = """? (192.168.53.1) at f0:18:98:11:22:33 on en0 ifscope [ethernet]
? (192.168.53.17) at 3c:22:fb:44:55:66 on en0 ifscope [ethernet]
? (192.168.53.88) at (incomplete) on en0 ifscope [ethernet]
"""

IP_NEIGH = """192.168.53.1 dev en0 lladdr f0:18:98:11:22:33 REACHABLE
192.168.53.17 dev en0 lladdr 3c:22:fb:44:55:66 STALE
192.168.53.88 dev en0  FAILED
fe80::1 dev en0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
"""


def test_parse_arp_an_reads_neighbours_and_their_hardware_addresses():
    peers = parse_arp_an(ARP_AN)
    assert len(peers) == 3
    gateway = peers[0]
    assert gateway.address == "192.168.53.1"
    assert gateway.mac == "f0:18:98:11:22:33"
    assert gateway.interface == "en0"
    assert gateway.identified is True
    # A neighbour that has not answered has an address but no identity.
    assert peers[2].identified is False


def test_parse_ip_neigh_reads_neighbours_and_their_hardware_addresses():
    peers = parse_ip_neigh(IP_NEIGH)
    assert len(peers) == 3
    gateway = peers[0]
    assert gateway.address == "192.168.53.1"
    assert gateway.mac == "f0:18:98:11:22:33"
    assert gateway.interface == "en0"
    assert gateway.state == "REACHABLE"
    assert peers[1].state == "STALE"
    assert peers[2].identified is False


def test_a_device_id_is_its_hardware_address_not_its_ip():
    """An address is not an identity: a DHCP lease moves and the device does not."""

    from surveyor.scanners.network import _device_id

    assert _device_id("f0:18:98:11:22:33") == "device:f0-18-98-11-22-33"


def test_parse_ifconfig_extracts_addresses_and_state():
    interfaces = {iface.name: iface for iface in parse_ifconfig(IFCONFIG)}
    en0 = interfaces["en0"]
    assert en0.mac == "f0:18:98:aa:bb:cc"
    assert en0.mtu == 1500
    assert en0.state == "active"
    assert en0.up is True
    assert en0.ipv4 == [("192.168.53.241", 24)]
    assert interfaces["en5"].state == "inactive"


def test_parse_ifconfig_reads_ipv6_too():
    """A dual-stacked box has two address families, and both are topology."""

    interfaces = {iface.name: iface for iface in parse_ifconfig(IFCONFIG)}
    en0 = interfaces["en0"]
    assert en0.ipv6 == [("fe80::1c2b:3c4d:5e6f:7081", 64)]
    assert en0.addressed is True


def test_parse_ip_addr_reads_ipv6_too():
    addr = (
        "2: enp0s31f6    inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic enp0s31f6\n"
        "2: enp0s31f6    inet6 2001:db8::1/64 scope global \n"
        "2: enp0s31f6    inet6 fe80::1/64 scope link\n"
    )
    interfaces = parse_ip_addr(addr)
    iface = interfaces[0]
    assert iface.ipv4 == [("10.0.0.5", 24)]
    assert iface.ipv6 == [("2001:db8::1", 64), ("fe80::1", 64)]


def test_parse_ip_addr_combines_link_and_address_views():
    addr = (
        "2: enp0s31f6    inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic enp0s31f6\n"
        "2: enp0s31f6    inet6 fe80::1/64 scope link\n"
    )
    link = (
        "2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel "
        "state UP mode DEFAULT group default qlen 1000    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
    )
    interfaces = parse_ip_addr(addr, link)
    assert len(interfaces) == 1
    iface = interfaces[0]
    assert iface.name == "enp0s31f6"
    assert iface.ipv4 == [("10.0.0.5", 24)]
    assert iface.mac == "aa:bb:cc:dd:ee:ff"
    assert iface.up is True


def test_parse_hardware_ports_maps_devices():
    text = (
        "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: f0:18:98:aa:bb:cc\n\n"
        "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
    )
    mapping = parse_hardware_ports(text)
    assert mapping == {"en0": "Wi-Fi", "bridge0": "Thunderbolt Bridge"}


def test_classification_prefers_infrastructure_over_port_name():
    assert classify("lo0") == "loopback"
    assert classify("en0", "Wi-Fi") == "wifi"
    assert classify("bridge0", "Thunderbolt Bridge") == "virtual"
    assert classify("en5", "Thunderbolt 5") == "thunderbolt"
    assert classify("en1", "Ethernet") == "ethernet"
    assert classify("utun4") == "virtual"
    assert classify("eth0") == "ethernet"
    assert classify("wlan0") == "wifi"


PMSET = """Now drawing from 'AC Power'
 -InternalBattery-0 (id=23199843)\t100%; charged; 0:00 remaining present: true
"""


def test_parse_pmset_reports_wall_power_and_battery():
    drawing, batteries = _parse_pmset_batt(PMSET)
    assert drawing == "AC Power"
    assert len(batteries) == 1
    battery = batteries[0]
    assert battery["charge_percent"] == 100
    assert battery["state"] == "charged"
    assert battery["minutes_remaining"] == 0
    assert battery["present"] is True


IOREG = """
    "CycleCount" = 87
    "DesignCapacity" = 8695
    "Temperature" = 303
    "BatterySerialNumber" = "D8TEST12345"
"""


def test_parse_ioreg_battery_reads_design_values():
    values = _parse_ioreg_battery(IOREG)
    assert values["CycleCount"] == 87
    assert values["DesignCapacity"] == 8695
    assert values["Temperature"] == 303
    assert values["BatterySerialNumber"] == "D8TEST12345"


def test_docker_published_ports_are_deduplicated():
    raw = "0.0.0.0:8080->80/tcp, :::8080->80/tcp, 0.0.0.0:9000->9000/udp"
    assert _published_ports(raw) == [(8080, 80, "tcp"), (9000, 9000, "udp")]


def test_compose_labels_are_parsed():
    labels = _parse_labels("com.docker.compose.project=stack,com.docker.compose.service=web")
    assert labels["com.docker.compose.project"] == "stack"
    assert labels["com.docker.compose.service"] == "web"


def test_bind_parsing_handles_ipv6_and_wildcards():
    assert _bind_of("*:8080") == ("*", 8080)
    assert _bind_of("127.0.0.1:11434") == ("127.0.0.1", 11434)
    assert _bind_of("[::1]:631") == ("::1", 631)
    assert _bind_of("0.0.0.0:5000") == ("0.0.0.0", 5000)
