"""Notification delivery: payloads, thresholds, and failure handling.

The webhook under test is a local HTTP server started by the test itself, so
these tests need no network and no third-party service.
"""

from __future__ import annotations

import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from conftest import build_topology, change_fact, change_telemetry
from surveyor.config import Config
from surveyor.differ import diff_topologies
from surveyor.errors import ConfigError
from surveyor.model import Topology
from surveyor.notify import (
    Notifier,
    build_payload,
    describe_endpoints,
    endpoint_style,
    mask_url,
    sample_payload,
    should_notify,
    summary_text,
)


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", errors="replace")}
        self.server.requests.append({"path": self.path, "payload": payload})
        status = self.server.status
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args) -> None:  # pragma: no cover - silence the server
        return


@pytest.fixture
def webhook():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    server.status = 200
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield server, f"http://{host}:{port}/services/T0/B1/secret"
    finally:
        server.shutdown()
        server.server_close()


def test_mask_url_hides_the_token():
    masked = mask_url("https://hooks.slack.com/services/T000/B000/SuperSecret")
    assert masked == "https://hooks.slack.com/***"
    assert "SuperSecret" not in masked


def test_mask_url_hides_userinfo_query_and_fragment():
    assert mask_url("https://user:password@example.test:8443/hook?token=secret#private") == (
        "https://example.test:8443/***"
    )
    assert mask_url("http://user:password@[::1]:8080/secret") == "http://[::1]:8080/***"
    assert mask_url("https://[broken/secret") == "***"


def test_transport_errors_never_echo_webhook_credentials(monkeypatch):
    endpoint = "https://user:password@example.test/hook/secret?token=private"
    transport = Mock(side_effect=urllib.error.URLError(f"could not reach {endpoint}"))
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    result = Notifier([endpoint], retries=0, backoff=0).ping()[0]
    assert not result.ok
    assert result.error == "URLError"
    assert result.endpoint == "https://example.test/***"
    for secret in ("user", "password", "secret", "private"):
        assert secret not in result.summary


def test_malformed_endpoint_is_reported_without_stopping_other_deliveries(monkeypatch):
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    transport = Mock(return_value=response)
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    endpoints = ["https://[broken/secret", "https://example.test/hook"]
    results = Notifier(endpoints, retries=0, backoff=0).ping()
    assert len(results) == 2
    assert not results[0].ok
    assert results[0].endpoint == "***"
    assert "secret" not in results[0].summary
    assert results[1].ok
    assert transport.call_count == 1


def test_oversized_payload_is_rejected_without_sending_partial_json(monkeypatch):
    transport = Mock()
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    monkeypatch.setattr("surveyor.notify._MAX_PAYLOAD_BYTES", 32)
    result = Notifier(["https://example.test/hook"], retries=0).ping()[0]
    assert not result.ok
    assert result.attempts == 0
    assert "payload exceeds" in result.error
    transport.assert_not_called()


def test_retry_backoff_only_happens_between_attempts(monkeypatch):
    transport = Mock(side_effect=TimeoutError("synthetic timeout"))
    sleep = Mock()
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    monkeypatch.setattr("surveyor.notify.time.sleep", sleep)
    result = Notifier(["https://example.test/hook"], retries=1, backoff=0.25).ping()[0]
    assert not result.ok
    assert result.attempts == 2
    sleep.assert_called_once_with(0.25)


def test_endpoint_styles_are_recognised():
    assert endpoint_style("https://hooks.slack.com/services/x") == "slack"
    assert endpoint_style("https://discord.com/api/webhooks/1/x") == "discord"
    assert endpoint_style("https://example.com/hook") == "generic"


def test_describe_endpoints_masks_tokens():
    text = describe_endpoints(["https://hooks.slack.com/services/T/B/secret"])
    assert "secret" not in text
    assert "hooks.slack.com" in text


def test_threshold_gating(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    assert should_notify(report, "warning") is True
    assert should_notify(report, "critical") is False
    assert should_notify(report, "never") is False

    unchanged = diff_topologies(topology, Topology.from_dict(topology.to_dict()))
    assert should_notify(unchanged, "notice") is False

    drifted = change_telemetry(topology, "host:lab", "load_1m", 5.0)
    telemetry_report = diff_topologies(topology, drifted)
    assert should_notify(telemetry_report, "notice") is False


def test_summary_mentions_the_change(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    text = summary_text(report, changed)
    assert "nginx:1.27" in text
    assert "test-site" in text  # the site name


def sample_payload_dialects(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)

    slack = build_payload(report, changed, endpoint="https://hooks.slack.com/services/x")
    assert "text" in slack

    discord = build_payload(report, changed, endpoint="https://discord.com/api/webhooks/1/x")
    assert "content" in discord

    generic = build_payload(report, changed, endpoint="https://example.com/hook")
    assert generic["source"] == "the-surveyor"
    assert generic["severity"] == "warning"
    assert generic["fingerprint"] == changed.fingerprint
    assert generic["changes"][0]["field"] == "image"


def test_sample_payload_is_style_aware():
    assert "text" in sample_payload("https://hooks.slack.com/services/x")
    assert "content" in sample_payload("https://discord.com/api/webhooks/1/x")
    assert sample_payload("https://example.com/hook")["severity"] == "notice"


def test_delivery_posts_the_payload(webhook):
    server, url = webhook
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    notifier = Notifier([url], timeout=5.0, on="warning", retries=0)
    results = notifier.send(report, changed)
    assert len(results) == 1
    assert results[0].ok is True
    assert results[0].status == 200
    assert "secret" not in results[0].endpoint
    assert len(server.requests) == 1
    assert server.requests[0]["payload"]["source"] == "the-surveyor"


def test_delivery_failure_is_reported_not_raised(monkeypatch):
    transport = Mock(side_effect=urllib.error.URLError("synthetic connection failure"))
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    notifier = Notifier(["https://example.test/nothing"], timeout=1.0, retries=0)
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    results = notifier.send(report, changed)
    assert results[0].ok is False
    assert results[0].error == "URLError"
    assert "nothing" not in results[0].endpoint
    transport.assert_called_once()


def test_server_errors_are_retried(webhook):
    server, url = webhook
    server.status = 500
    notifier = Notifier([url], timeout=5.0, retries=1, backoff=0.0)
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    results = notifier.send(report, changed)
    assert results[0].ok is False
    assert results[0].attempts == 2
    assert len(server.requests) == 2


def test_client_errors_are_not_retried(webhook):
    server, url = webhook
    server.status = 404
    notifier = Notifier([url], timeout=5.0, retries=2, backoff=0.0)
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    results = notifier.send(report, changed)
    assert results[0].ok is False
    assert results[0].attempts == 1
    assert len(server.requests) == 1


def test_dry_run_sends_nothing(webhook):
    server, url = webhook
    notifier = Notifier([url], timeout=5.0, dry_run=True)
    results = notifier.ping()
    assert results[0].ok is True
    assert server.requests == []


def test_threshold_blocks_delivery(webhook):
    server, url = webhook
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    notifier = Notifier([url], timeout=5.0, on="critical")
    assert notifier.send(report, changed) == []
    assert server.requests == []


def test_config_accepts_endpoints_from_file_and_env(tmp_path, monkeypatch):
    path = tmp_path / "surveyor.toml"
    path.write_text('notify = ["https://hooks.slack.com/services/a/b/c"]\nnotify_on = "critical"\n')
    config = Config.load(path)
    assert config.notify == ("https://hooks.slack.com/services/a/b/c",)
    assert config.notify_on == "critical"

    monkeypatch.setenv("SURVEYOR_NOTIFY", "https://example.com/a,https://example.com/b")
    monkeypatch.setenv("SURVEYOR_NOTIFY_ON", "notice")
    env_config = Config.load()
    assert env_config.notify == ("https://example.com/a", "https://example.com/b")
    assert env_config.notify_on == "notice"


def test_config_rejects_bad_endpoints_and_thresholds():
    with pytest.raises(ConfigError, match="http"):
        Config(notify=("ftp://example.com/x",))
    with pytest.raises(ConfigError, match="notify_on"):
        Config(notify_on="loud")
    with pytest.raises(ConfigError, match="notify_format"):
        Config(notify_format="carrier-pigeon")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------
def _stub_survey(monkeypatch, topologies):
    """Replace the real scanners with a queue of prepared plats."""

    from surveyor.compiler import CompilationReport

    queue = list(topologies)

    def fake_survey(config, *, site=None, progress=None, salt="", **kwargs):
        topology = queue.pop(0) if len(queue) > 1 else queue[0]
        return CompilationReport(topology=topology)

    monkeypatch.setattr("surveyor.cli.survey", fake_survey)


def test_notify_command_requires_an_endpoint(capsys):
    from surveyor import cli

    assert cli.main(["notify"]) == 1
    assert "no webhook configured" in capsys.readouterr().err


def test_notify_command_dry_run_prints_the_payload(capsys):
    from surveyor import cli

    assert cli.main(["notify", "--dry-run", "--notify", "http://127.0.0.1:9/hook"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "http://127.0.0.1:9/***" in payload


def test_notify_command_delivers(webhook, capsys):
    from surveyor import cli

    server, url = webhook
    assert cli.main(["notify", "--notify", url]) == 0
    assert "delivered" in capsys.readouterr().out
    assert len(server.requests) == 1


def test_notify_command_reports_failure(capsys, monkeypatch, tmp_path):
    from surveyor import cli

    transport = Mock(side_effect=urllib.error.URLError("synthetic connection failure"))
    monkeypatch.setattr("surveyor.notify.urllib.request.urlopen", transport)
    monkeypatch.setattr("surveyor.notify.time.sleep", Mock())
    monkeypatch.setattr("surveyor.cli.Config.load", Mock(return_value=Config(store=tmp_path / "ledger")))
    assert cli.main(["notify", "--notify", "https://example.test/hook"]) == 1
    assert "failed" in capsys.readouterr().err
    assert transport.call_count == 2


def test_scan_notifies_on_a_structural_change(webhook, tmp_path, monkeypatch, capsys):
    """A workload image change is a warning, so it clears the default gate."""

    from surveyor import cli

    server, url = webhook
    first = build_topology()
    second = change_fact(first, "workload:docker:web", "image", "nginx:1.27")
    _stub_survey(monkeypatch, [first, second])

    store = tmp_path / "ledger"
    assert cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"]) == 0
    assert cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"]) == 0
    capsys.readouterr()
    # The first plat is only "notice" level, so the second scan is the one
    # that carries a warning.
    assert len(server.requests) == 2
    body = server.requests[-1]["payload"]
    assert body["severity"] == "warning"
    assert body["changes"][0]["field"] == "image"


def test_scan_notifies_on_a_critical_change(webhook, tmp_path, monkeypatch, capsys):
    from conftest import without_node
    from surveyor import cli

    server, url = webhook
    first = build_topology()
    second = without_node(first, "host:lab")
    _stub_survey(monkeypatch, [first, second])

    store = tmp_path / "ledger"
    cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"])
    cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"])
    capsys.readouterr()
    assert server.requests[-1]["payload"]["severity"] == "critical"


def test_scan_does_not_notify_when_nothing_structural_changed(webhook, tmp_path, monkeypatch, capsys):
    from surveyor import cli

    server, url = webhook
    _stub_survey(monkeypatch, [build_topology()])

    store = tmp_path / "ledger"
    cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"])
    cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice"])
    capsys.readouterr()
    assert len(server.requests) == 1  # the first plat only


def test_scan_no_notify_suppresses_delivery(webhook, tmp_path, monkeypatch, capsys):
    from surveyor import cli

    server, url = webhook
    _stub_survey(monkeypatch, [build_topology()])
    store = tmp_path / "ledger"
    cli.main(["--store", str(store), "scan", "--notify", url, "--notify-on", "notice", "--no-notify"])
    capsys.readouterr()
    assert server.requests == []


def test_daemon_notifies_once_per_change(webhook, tmp_path, monkeypatch, capsys):
    from surveyor import cli

    server, url = webhook
    first = build_topology()
    second = change_fact(first, "workload:docker:web", "image", "nginx:1.27")
    _stub_survey(monkeypatch, [first, second])

    store = tmp_path / "ledger"
    assert cli.main(["--store", str(store), "daemon", "--once", "--notify", url, "--notify-on", "notice"]) == 0
    capsys.readouterr()
    assert len(server.requests) == 1
    assert server.requests[0]["payload"]["source"] == "the-surveyor"
