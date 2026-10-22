from __future__ import annotations

from surveyor.scanners.network import (
    classify,
    parse_hardware_ports,
    parse_ifconfig,
    parse_ip_addr,
)
from surveyor.scanners.power import _parse_ioreg_battery, _parse_pmset_batt
from surveyor.scanners.workloads import _bind_of, _parse_labels, _published_ports

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


def test_parse_ifconfig_extracts_addresses_and_state():
    interfaces = {iface.name: iface for iface in parse_ifconfig(IFCONFIG)}
    en0 = interfaces["en0"]
    assert en0.mac == "f0:18:98:aa:bb:cc"
    assert en0.mtu == 1500
    assert en0.state == "active"
    assert en0.up is True
    assert en0.ipv4 == [("192.168.53.241", 24)]
    assert interfaces["en5"].state == "inactive"


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
