from __future__ import annotations

from surveyor.model import Topology
from surveyor.redact import (
    alias_secret,
    is_public,
    mask_ip,
    mask_mac,
    redact_topology,
)


def test_mac_addresses_keep_only_the_vendor_prefix():
    assert mask_mac("ether f0:18:98:aa:bb:cc") == "ether f0:18:98:xx:xx:xx"


def test_public_addresses_lose_their_host_bits():
    assert mask_ip("93.184.216.34") == "93.184.x.x"
    assert mask_ip("8.8.8.8") == "8.8.x.x"


def test_private_and_loopback_addresses_survive():
    for address in ("192.168.53.9", "10.0.0.5", "127.0.0.1"):
        assert mask_ip(address) == address


def test_public_detection():
    assert is_public("1.1.1.1") is True
    assert is_public("192.168.1.1") is False
    assert is_public("not-an-ip") is False


def test_alias_is_stable_and_short():
    first = alias_secret("C02TEST123")
    second = alias_secret("C02TEST123")
    assert first == second
    assert first.startswith("sha256:")
    assert len(first) < 24


def test_redaction_preserves_structure_but_hides_identifiers(topology):
    redacted = redact_topology(topology)
    assert set(redacted.nodes) == set(topology.nodes)
    assert len(redacted.edges) == len(topology.edges)
    assert redacted.observations["redacted"] is True

    host = redacted.nodes["host:lab"]
    assert host.facts["mac"] == "f0:18:98:xx:xx:xx"
    battery = redacted.nodes["power:battery:internal-0"]
    assert battery.facts["serial"].startswith("sha256:")
    assert battery.facts["serial"] != "C02TEST123"
    # The unredacted survey still holds the real value.
    assert topology.nodes["power:battery:internal-0"].facts["serial"] == "C02TEST123"


def test_redaction_aliases_wifi_ssids():
    from surveyor.model import Node

    survey = Topology(site="x")
    survey.add(Node("iface:x:en0", "interface", "en0", facts={"wifi_ssid": "Hamanaka HQ"}))
    redacted = redact_topology(survey)
    alias = redacted.nodes["iface:x:en0"].facts["wifi_ssid"]
    assert alias.startswith("sha256:")
    assert "Hamanaka" not in alias


def test_observation_notes_are_masked_too(topology):
    topology.observations = {
        "warnings": ["interface f0:18:98:aa:bb:cc took 93.184.216.34 as a peer"],
        "conflicts": [],
    }
    redacted = redact_topology(topology)
    warning = redacted.observations["warnings"][0]
    assert "f0:18:98:aa:bb:cc" not in warning
    assert "93.184.216.34" not in warning
    assert "f0:18:98:xx:xx:xx" in warning


def test_redacted_documents_are_self_consistent(topology):
    redacted = redact_topology(topology)
    document = redacted.to_dict()
    restored = Topology.from_dict(document)
    assert restored.fingerprint == redacted.fingerprint
    assert restored.fingerprint == document["fingerprint"]
    assert restored.digest == redacted.digest
