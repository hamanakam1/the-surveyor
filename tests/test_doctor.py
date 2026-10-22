"""The doctor: what can this machine actually be surveyed for?

The first question on an unfamiliar box is always "why is my power layer
empty?", and the answer is always one of three things: the tool is not
installed, the tool is not on the allowlist, or the scanner was told to skip
it. The doctor answers all three without running a survey.
"""

from __future__ import annotations

from surveyor.config import Config
from surveyor.doctor import examine, render
from surveyor.scanners.base import registry


def test_every_scanner_declares_its_tools():
    """A scanner that does not say what it needs cannot be diagnosed."""

    for name, spec in registry().items():
        assert spec.tools, f"{name} declares no tools"
        assert set(spec.tools) <= {"darwin", "linux", "any"}


def test_the_report_names_the_platform_and_the_store():
    report = examine(Config(), config_path="")
    assert report.platform
    assert report.python
    assert report.store
    assert report.scanners


def test_a_scanner_with_no_tools_for_this_platform_is_ready():
    """The Linux power layer reads /sys directly and needs no program."""

    report = examine(Config())
    power = next(item for item in report.scanners if item.name == "power")
    if report.platform.startswith("linux"):
        assert power.tools == []
        assert power.ready is True


def test_the_report_lists_the_allowlisted_tools():
    report = examine(Config())
    assert report.tools
    for tool in report.tools:
        assert tool.name
        assert isinstance(tool.available, bool)


def test_the_report_is_json_serialisable():
    import json

    report = examine(Config())
    rendered = json.dumps(report.to_dict())
    assert "scanners" in rendered
    assert "tools" in rendered


def test_the_rendered_report_reads_as_a_report():
    text = render(examine(Config()))
    assert "the-surveyor" in text
    assert "platform" in text
    assert "store" in text


def test_a_scanner_that_needs_a_missing_tool_is_a_problem():
    from surveyor.doctor import ScannerStatus, ToolStatus

    status = ScannerStatus(
        name="example",
        layer="network",
        description="",
        enabled=True,
        tools=[ToolStatus(name="nowhere", available=False)],
    )
    assert status.ready is False
    assert status.missing == ["nowhere"]
