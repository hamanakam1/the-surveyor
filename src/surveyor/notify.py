"""Outbound notifications: tell someone when the map actually changed.

Rules that keep a notifier from becoming a liability:

* **It never breaks a survey.** Every failure is caught and reported as a
  result. A dead webhook must not stop a daemon or fail a `scan`.
* **It only fires on structural change.** Telemetry drift is not an event.
* **It does not leak credentials.** Webhook URLs contain bearer tokens, so
  they are masked in every message, log line, and exception text.
* **It is dumb about payloads.** Slack gets Slack's shape, Discord gets
  Discord's, everything else gets a documented generic JSON document.

Transport is plain ``urllib`` over HTTPS -- no dependency, no SDK, no account.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .differ import CRITICAL, INFO, NOTICE, WARNING, DiffReport
from .model import Topology
from .util import clip, short_digest

#: Severity ranking, loudest first.
RANK: dict[str, int] = {CRITICAL: 3, WARNING: 2, NOTICE: 1, INFO: 0}

#: Accepted thresholds for ``notify_on``.
THRESHOLDS: tuple[str, ...] = ("critical", "warning", "notice", "never")

FORMATS: tuple[str, ...] = ("text", "markdown")

_MAX_TEXT = 2500
_MAX_CHANGES = 50
_MAX_PAYLOAD_BYTES = 120_000


@dataclass(slots=True)
class Notification:
    """Outcome of one delivery attempt to one endpoint."""

    endpoint: str
    ok: bool
    status: int | None = None
    error: str = ""
    attempts: int = 0

    @property
    def summary(self) -> str:
        if self.ok:
            return f"{self.endpoint}: delivered ({self.status})"
        return f"{self.endpoint}: failed ({self.error})"


def mask_url(url: str) -> str:
    """Hide the token part of a webhook URL while keeping it recognisable."""

    parsed = urlparse(url)
    if not parsed.netloc:
        return "***"
    return f"{parsed.scheme}://{parsed.netloc}/***"


def endpoint_style(url: str) -> str:
    """Pick a payload dialect for a known webhook host."""

    host = (urlparse(url).netloc or "").lower()
    if "hooks.slack.com" in host:
        return "slack"
    if "discord.com" in host or "discordapp.com" in host:
        return "discord"
    if "mattermost" in host:
        return "mattermost"
    if "ntfy.sh" in host:
        return "ntfy"
    return "generic"


def severity_of(report: DiffReport) -> str:
    """The loudest structural severity present in a report."""

    best = ""
    best_rank = -1
    for change in report.changes:
        if change.severity == INFO:
            continue
        rank = RANK.get(change.severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = change.severity
    return best


def should_notify(report: DiffReport, threshold: str) -> bool:
    """Decide whether a report clears the configured threshold."""

    if threshold == "never":
        return False
    if not report.structural:
        return False
    loudest = severity_of(report)
    if not loudest:
        return False
    return RANK.get(loudest, 0) >= RANK.get(threshold, RANK[WARNING])


def _change_rows(report: DiffReport, limit: int = _MAX_CHANGES) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for change in report.changes[:limit]:
        if change.severity == INFO:
            continue
        rows.append(
            {
                "action": change.action,
                "severity": change.severity,
                "entity_type": change.entity_type,
                "name": change.label or change.entity,
                "field": change.field,
                "before": change.before,
                "after": change.after,
            }
        )
    return rows


def summary_text(report: DiffReport, topology: Topology, *, markdown: bool = False) -> str:
    """A short human summary, suitable for a chat message."""

    loudest = severity_of(report) or WARNING
    lines = [
        f"The Surveyor: {report.headline()} on {topology.site}",
    ]
    if markdown:
        lines.append(f"*severity:* `{loudest}`  *plat:* `{short_digest(topology.digest)}`")
    else:
        lines.append(f"severity: {loudest} · plat: {short_digest(topology.digest)}")

    for change in report.changes[:12]:
        if change.severity == INFO:
            continue
        name = change.label or change.entity
        if change.action == "modified":
            detail = f"{change.field}: {clip(change.before, 40)} -> {clip(change.after, 40)}"
            lines.append(f"- {name} ({detail})")
        else:
            lines.append(f"- {change.action} {name}")
    remaining = len([c for c in report.changes if c.severity != INFO]) - 12
    if remaining > 0:
        lines.append(f"- … {remaining} more change(s)")
    lines.append(f"fingerprint: {topology.fingerprint}")
    return "\n".join(lines)[:_MAX_TEXT]


def build_payload(
    report: DiffReport,
    topology: Topology,
    *,
    endpoint: str = "",
    markdown: bool = False,
) -> dict[str, Any]:
    """Build the JSON body for a webhook endpoint."""

    style = endpoint_style(endpoint) if endpoint else "generic"
    text = summary_text(report, topology, markdown=markdown)
    loudest = severity_of(report) or WARNING
    rows = _change_rows(report)

    if style == "slack":
        payload: dict[str, Any] = {"text": text}
        if markdown:
            payload["blocks"] = [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text},
                }
            ]
        return payload

    if style == "discord":
        return {"content": text[:1900]}

    if style == "mattermost":
        return {"text": text, "username": "the-surveyor"}

    if style == "ntfy":
        priority = {"critical": "urgent", "warning": "high"}.get(loudest, "default")
        return {
            "topic": topology.site,
            "title": "The Surveyor",
            "message": text,
            "priority": priority,
        }

    return {
        "source": "the-surveyor",
        "site": topology.site,
        "severity": loudest,
        "headline": report.headline(),
        "text": text,
        "markdown": text if markdown else None,
        "generated_at": topology.generated_at,
        "plat_digest": topology.digest,
        "fingerprint": topology.fingerprint,
        "counts": topology.counts(),
        "changes": rows,
    }


@dataclass(slots=True)
class Notifier:
    """Delivers survey change notifications to one or more webhooks."""

    endpoints: Sequence[str] = ()
    timeout: float = 10.0
    retries: int = 1
    format: str = "text"
    on: str = "warning"
    dry_run: bool = False
    backoff: float = 1.0
    results: list[Notification] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.endpoints = tuple(endpoint.strip() for endpoint in self.endpoints if endpoint.strip())
        if self.format not in FORMATS:
            raise ValueError(f"notify format must be one of {', '.join(FORMATS)}")
        if self.on not in THRESHOLDS:
            raise ValueError(f"notify_on must be one of {', '.join(THRESHOLDS)}")

    @property
    def enabled(self) -> bool:
        return bool(self.endpoints)

    def send(
        self,
        report: DiffReport,
        topology: Topology,
        *,
        force: bool = False,
    ) -> list[Notification]:
        """Deliver a notification if the report clears the threshold."""

        if not self.endpoints:
            return []
        if not force and not should_notify(report, self.on):
            return []
        markdown = self.format == "markdown"
        for endpoint in self.endpoints:
            payload = build_payload(report, topology, endpoint=endpoint, markdown=markdown)
            self.results.append(self._deliver(endpoint, payload))
        return list(self.results)

    def ping(self) -> list[Notification]:
        """Send a test payload to every endpoint, ignoring the threshold."""

        results: list[Notification] = []
        for endpoint in self.endpoints:
            payload = sample_payload(endpoint)
            results.append(self._deliver(endpoint, payload))
        self.results.extend(results)
        return results

    def _deliver(self, endpoint: str, payload: dict[str, Any]) -> Notification:
        body = json.dumps(payload, default=str).encode("utf-8")
        if len(body) > _MAX_PAYLOAD_BYTES:
            body = body[:_MAX_PAYLOAD_BYTES]
        if self.dry_run:
            return Notification(endpoint=mask_url(endpoint), ok=True, status=0, attempts=0)

        attempts = 0
        last_error = ""
        status: int | None = None
        for attempt in range(max(1, self.retries + 1)):
            attempts += 1
            request = urllib.request.Request(  # noqa: S310 - operator-configured endpoint
                endpoint,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "the-surveyor/1.0",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - operator-configured endpoint
                    status = int(getattr(response, "status", 200) or 200)
                    response.read(4096)
                return Notification(endpoint=mask_url(endpoint), ok=True, status=status, attempts=attempts)
            except urllib.error.HTTPError as exc:
                status = exc.code
                last_error = f"HTTP {exc.code}"
                if exc.code < 500:
                    break  # a 4xx will not fix itself
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            if attempt < max(1, self.retries + 1) and self.backoff:
                time.sleep(self.backoff)
        return Notification(
            endpoint=mask_url(endpoint),
            ok=False,
            status=status,
            error=last_error or "unknown failure",
            attempts=attempts,
        )


TEST_TEXT = (
    "Test notification from the-surveyor.\n"
    "If you can read this, the webhook is wired correctly. "
    "Nothing was surveyed and nothing changed."
)


def sample_payload(endpoint: str = "") -> dict[str, Any]:
    """A synthetic payload for `surveyor notify`."""

    style = endpoint_style(endpoint) if endpoint else "generic"
    if style == "slack":
        return {"text": TEST_TEXT}
    if style == "discord":
        return {"content": TEST_TEXT}
    if style == "mattermost":
        return {"text": TEST_TEXT, "username": "the-surveyor"}
    if style == "ntfy":
        return {"topic": "the-surveyor", "title": "the-surveyor", "message": TEST_TEXT}
    return {
        "source": "the-surveyor",
        "severity": "notice",
        "headline": "Test notification from the-surveyor",
        "text": TEST_TEXT,
    }


def describe_endpoints(endpoints: Iterable[str]) -> str:
    """Human summary of configured endpoints, tokens hidden."""

    masked = [mask_url(endpoint) for endpoint in endpoints]
    if not masked:
        return "no notification endpoints configured"
    return ", ".join(masked)
