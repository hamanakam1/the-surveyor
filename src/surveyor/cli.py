"""Command line interface for The Surveyor.

Every command is read-only with respect to the surveyed machine. Writes are
confined to the ledger directory (``~/.surveyor/ledger`` by default) and to
files the operator names explicitly.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import OET_VERSION, __version__
from .ascii import BANNER, LEGEND, SHORT, TAGLINE, banner, supports_color
from .compiler import survey
from .config import Config, ConfigError, default_config_path, default_store
from .daemon import format_daemon_start, run_daemon
from .differ import diff_topologies, render_text
from .errors import SchemaError, StoreError, SurveyorError
from .model import LAYERS, Topology
from .notify import Notifier, mask_url, sample_payload
from .render import ascii_map, markdown_table, mermaid
from .scanners.base import registry
from .scribe import compose_changelog
from .store import Ledger
from .util import short_digest, slug
from .validation import Problem, validate_document

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CHANGED = 3


# --------------------------------------------------------------------------
# argument plumbing
# --------------------------------------------------------------------------
def _common_flags() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, help="configuration file (.toml/.json/.yaml)")
    common.add_argument("--store", default=argparse.SUPPRESS, help="ledger directory")
    common.add_argument("--site", default=argparse.SUPPRESS, help="site name recorded with each plat")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable ANSI colour")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_flags()
    parser = argparse.ArgumentParser(
        prog="surveyor",
        description="Take bearings on real hardware and record the map that is actually there.",
        parents=[common],
        epilog="Run `surveyor <command> --help` for command-specific flags.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"the-surveyor {__version__} (OET {OET_VERSION})",
    )
    parser.set_defaults(handler=_cmd_root)
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    scan = subparsers.add_parser("scan", parents=[common], help="survey now and record the plat")
    scan.add_argument("--output", "--out", dest="output", help="also write the OET document here")
    scan.add_argument("--scanners", help="comma-separated subset of scanners")
    scan.add_argument("--redact", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS,
                      help="mask identifiers before recording (default: config)")
    scan.add_argument("--force", action="store_true", help="record even when the fingerprint is unchanged")
    scan.add_argument("--no-save", action="store_true", help="survey without touching the ledger")
    scan.add_argument("--no-changelog", action="store_true", help="do not write a changelog file")
    scan.add_argument("--ascii", action="store_true", help="print the layered ASCII map")
    scan.add_argument("--json", action="store_true", help="machine-readable summary")
    scan.add_argument("--quiet", action="store_true", help="only print the outcome")
    scan.add_argument("--notify", action="append", metavar="URL",
                      help="webhook to notify on a structural change (repeatable)")
    scan.add_argument("--notify-on", choices=("critical", "warning", "notice", "never"),
                      help="severity threshold for notifications (default: warning)")
    scan.add_argument("--no-notify", action="store_true", help="ignore configured webhooks")
    scan.set_defaults(handler=_cmd_scan)

    diff = subparsers.add_parser("diff", parents=[common], help="compare two survey plats")
    diff.add_argument("--from", dest="from_ref", default=None, help="older plat (seq, digest prefix, HEAD~1, or file)")
    diff.add_argument("--to", dest="to_ref", default=None, help="newer plat (default HEAD)")
    diff.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    diff.add_argument("--polish", action="store_true", help="let the local model rewrite the narrative")
    diff.add_argument("--verbose", action="store_true", help="include telemetry drift")
    diff.add_argument("--exit-code", action="store_true", help="exit 3 when the structure changed")
    diff.set_defaults(handler=_cmd_diff)

    log = subparsers.add_parser("log", parents=[common], help="list recorded surveys")
    log.add_argument("-n", "--limit", type=int, default=20, help="entries to show (default 20)")
    log.add_argument("--json", action="store_true")
    log.set_defaults(handler=_cmd_log)

    history = subparsers.add_parser(
        "history", parents=[common], help="what changed, and when it changed"
    )
    history.add_argument("-n", "--limit", type=int, default=20, help="changes to show")
    history.add_argument("--json", action="store_true")
    history.set_defaults(handler=_cmd_history)

    doctor = subparsers.add_parser(
        "doctor", parents=[common], help="say what this machine lets the Surveyor see"
    )
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=_cmd_doctor)

    show = subparsers.add_parser("show", parents=[common], help="print a recorded plat")
    show.add_argument("ref", nargs="?", default="HEAD", help="seq, digest prefix, or file (default HEAD)")
    show.add_argument("--format", choices=("ascii", "markdown", "mermaid", "json"), default="ascii")
    show.add_argument("--output", "--out", dest="output", help="write to a file instead of stdout")
    show.add_argument("--layer", default=None, help="only this layer (power, metal, network, workload)")
    show.add_argument("--kind", default=None, help="only this kind of node")
    show.add_argument("--tag", default=None, help="only nodes carrying this tag")
    show.set_defaults(handler=_cmd_show)

    verify = subparsers.add_parser("verify", parents=[common], help="verify ledger integrity and hash chain")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=_cmd_verify)

    daemon = subparsers.add_parser("daemon", parents=[common], help="survey on a schedule")
    daemon.add_argument("--interval", type=int, default=None, help="seconds between surveys")
    daemon.add_argument("--once", action="store_true", help="run a single cycle")
    daemon.add_argument("--max-cycles", type=int, default=None, help="stop after N cycles")
    daemon.add_argument("--json-lines", action="store_true", help="emit one JSON object per cycle")
    daemon.add_argument("--notify", action="append", metavar="URL",
                        help="webhook to notify on a structural change (repeatable)")
    daemon.add_argument("--notify-on", choices=("critical", "warning", "notice", "never"),
                        help="severity threshold for notifications (default: warning)")
    daemon.add_argument("--no-notify", action="store_true", help="ignore configured webhooks")
    daemon.set_defaults(handler=_cmd_daemon)

    scanners = subparsers.add_parser("scanners", help="list available scanners")
    scanners.add_argument("--json", action="store_true")
    scanners.set_defaults(handler=_cmd_scanners)

    init = subparsers.add_parser("init", parents=[common], help="write a starter configuration")
    init.add_argument("--path", default=None, help="where to write the config")
    init.add_argument("--force", action="store_true", help="overwrite an existing config")
    init.set_defaults(handler=_cmd_init)

    validate = subparsers.add_parser("validate", help="check an OET document against the schema rules")
    validate.add_argument("path", help="OET JSON file")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(handler=_cmd_validate)

    redact = subparsers.add_parser(
        "redact", help="mask identifiers in a plat, and audit what survived"
    )
    redact.add_argument("path", nargs="?", default="HEAD", help="OET file or plat reference (default HEAD)")
    redact.add_argument("--output", "--out", dest="output", help="write the redacted plat here")
    redact.add_argument("--audit", action="store_true", help="report identifiers that survived")
    redact.add_argument("--json", action="store_true")
    redact.set_defaults(handler=_cmd_redact)

    ping = subparsers.add_parser("notify", parents=[common],
                                  help="send a test notification to the configured webhooks")
    ping.add_argument("--notify", action="append", metavar="URL", help="webhook to test (repeatable)")
    ping.add_argument("--notify-on", choices=("critical", "warning", "notice", "never"))
    ping.add_argument("--no-notify", action="store_true", help="ignore configured webhooks")
    ping.add_argument("--dry-run", action="store_true", help="print the payload instead of sending it")
    ping.add_argument("--json", action="store_true")
    ping.set_defaults(handler=_cmd_notify)

    export = subparsers.add_parser(
        "export", help="write a plat out as a document another ledger can read"
    )
    export.add_argument("ref", nargs="?", default="HEAD", help="plat reference (default HEAD)")
    export.add_argument("--output", "--out", dest="output", help="write the document here")
    export.add_argument("--redact", action="store_true", help="mask identifiers first")
    export.add_argument(
        "--repo",
        default=None,
        help="write into a directory tree of plats, one file per site and host",
    )
    export.set_defaults(handler=_cmd_export)

    importer = subparsers.add_parser(
        "import", help="record a plat that came from another host"
    )
    importer.add_argument("path", help="OET JSON file")
    importer.add_argument("--host", default=None, help="host id the plat describes")
    importer.add_argument("--note", default="", help="a note to record with the import")
    importer.add_argument("--force", action="store_true", help="record even if nothing changed")
    importer.add_argument("--json", action="store_true")
    importer.set_defaults(handler=_cmd_import)

    fleet = subparsers.add_parser(
        "fleet", help="compose every host in the ledger into one map"
    )
    fleet.add_argument(
        "--site", default=None, help="only the hosts of this site"
    )
    fleet.add_argument(
        "--format",
        choices=("ascii", "markdown", "mermaid", "json"),
        default="ascii",
    )
    fleet.add_argument("--output", "--out", dest="output", help="write the map here")
    fleet.add_argument("--json", action="store_true", help="print a summary instead")
    fleet.set_defaults(handler=_cmd_fleet)

    art = subparsers.add_parser("banner", help="print the banner")
    art.set_defaults(handler=_cmd_banner)

    return parser


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _config(args: argparse.Namespace) -> Config:
    config = Config.load(getattr(args, "config", None))
    overrides: dict[str, Any] = {}
    if getattr(args, "store", None):
        overrides["store"] = Path(args.store).expanduser()
    if getattr(args, "site", None):
        overrides["site"] = args.site
    if hasattr(args, "scanners") and args.scanners:
        overrides["scanners"] = tuple(
            part.strip().lower() for part in args.scanners.split(",") if part.strip()
        )
    if hasattr(args, "redact"):
        overrides["redact"] = bool(args.redact)
    if getattr(args, "notify", None):
        overrides["notify"] = tuple(args.notify)
    if getattr(args, "notify_on", None):
        overrides["notify_on"] = args.notify_on
    if getattr(args, "no_notify", False):
        overrides["notify"] = ()
    return config.with_overrides(**overrides)


def _color(args: argparse.Namespace) -> bool:
    return supports_color(sys.stdout) and not getattr(args, "no_color", False)


def _resolve_ledger(args: argparse.Namespace) -> Ledger:
    return Ledger(_config(args).store)


def _salt_for(config: Config, ledger: Ledger) -> str:
    """The redaction key, but only when redaction is actually happening.

    Reading it creates the key file, so a scan that never redacts should not
    leave one behind.
    """

    if not config.redact:
        return ""
    return ledger.salt


def _parse_ref(ref: str, ledger: Ledger) -> tuple[Topology | None, str]:
    """Resolve a user-supplied plat reference to a topology."""

    candidate = Path(ref).expanduser()
    if candidate.exists() and candidate.is_file():
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SchemaError(f"{candidate}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        return Topology.from_dict(data), candidate.name

    entries = ledger.history()
    if not entries:
        if ref in {"HEAD", "HEAD~1"}:
            return None, "empty ledger"
        raise StoreError(f"ledger at {ledger.root} is empty; cannot resolve {ref!r}")

    if ref == "HEAD":
        entry = ledger.head()
        if entry is None:
            return None, "empty ledger"
        return ledger.get(entry.digest), f"#{entry.seq}"
    if ref.startswith("HEAD~"):
        # HEAD~N is the Nth local survey before this one.
        try:
            offset = int(ref[5:])
        except ValueError:
            raise StoreError(f"cannot resolve {ref!r}") from None
        if offset < 0:
            raise StoreError(f"cannot resolve {ref!r}")
        entry = ledger.head()
        for _ in range(offset):
            if entry is None:
                return None, "before the first survey"
            entry = ledger.previous_local(entry)
        if entry is None:
            return None, "before the first survey"
        return ledger.get(entry.digest), f"#{entry.seq}"
    if ref.isdigit():
        entry = ledger.entry_at(int(ref))
        return ledger.get(entry.digest), f"#{entry.seq}"

    # A host id names the newest plat imported from that host.
    imported = ledger.import_of(ref)
    if imported is not None:
        return ledger.get(imported.digest), f"#{imported.seq}"

    matches = [
        entry
        for entry in entries
        if entry.digest.split(":", 1)[-1].startswith(ref.split(":", 1)[-1])
    ]
    if not matches:
        raise StoreError(f"no recorded survey matches {ref!r}")
    if len(matches) > 1:
        raise StoreError(f"{ref!r} is ambiguous ({len(matches)} surveys match); use more characters")
    entry = matches[0]
    return ledger.get(entry.digest), f"#{entry.seq}"


def _count(number: int, noun: str) -> str:
    """``1 node`` reads better than ``1 nodes``."""

    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def _cmd_root(args: argparse.Namespace) -> int:
    print(banner(color=_color(args)))
    print()
    print(TAGLINE)
    print(LEGEND)
    print()
    print(f"the-surveyor {__version__} · OET {OET_VERSION} · zero dependencies · read-only observer")
    print("Run `surveyor --help` to choose a bearing (command).")
    return EXIT_OK


def _cmd_banner(args: argparse.Namespace) -> int:
    print(banner(color=_color(args)))
    print()
    print(TAGLINE)
    print(LEGEND)
    return EXIT_OK


def _cmd_scanners(args: argparse.Namespace) -> int:
    specs = registry()
    if args.json:
        _emit_json(
            [
                {"name": spec.name, "layer": spec.layer, "description": spec.description}
                for spec in specs.values()
            ]
        )
        return EXIT_OK
    print(f"{len(specs)} scanners available")
    for spec in specs.values():
        print(f"  {spec.name:<10} {spec.layer:<8} {spec.description}")
    return EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser() if args.path else default_config_path()
    if path.exists() and not args.force:
        raise ConfigError(f"{path} already exists; pass --force to overwrite")
    config = Config.load(getattr(args, "config", None)) if getattr(args, "config", None) else Config()
    if getattr(args, "store", None):
        config = config.with_overrides(store=Path(args.store).expanduser())
    if getattr(args, "site", None):
        config = config.with_overrides(site=args.site)
    _write_text(path, config.to_toml())
    Ledger(config.store).ensure()
    print(f"wrote {path}")
    print(f"ledger {config.store}")
    print("next: surveyor scan --ascii")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _config(args)
    ledger = Ledger(config.store)
    quiet = args.quiet or args.json

    if not quiet:
        print(f"◈ surveying {config.site} · {config.describe()}")

    def progress(message: str) -> None:
        if not quiet:
            print(f"  · {message}")

    report = survey(config, progress=progress, salt=_salt_for(config, ledger))
    topology = report.topology

    if report.failures and not args.json:
        for result in report.failures:
            print(f"  ! {result.scanner}: {result.error}", file=sys.stderr)

    head = ledger.head()
    previous = ledger.get(head.digest) if head else None
    diff = diff_topologies(previous, topology)

    commit = None
    changelog_path: Path | None = None
    if not args.no_save:
        commit = ledger.commit(topology, force=args.force)
        if commit.created and diff.structural and not args.no_changelog:
            output = compose_changelog(diff, topology, previous=previous, config=config)
            changelog_path = ledger.write_change(commit.entry, output.markdown)

    notifications = []
    if config.notify and diff.structural:
        notifier = Notifier(
            config.notify,
            timeout=config.notify_timeout,
            format=config.notify_format,
            on=config.notify_on,
        )
        notifications = notifier.send(diff, topology)

    if args.output:
        document = json.dumps(topology.to_dict(), indent=2, sort_keys=True)
        _write_text(Path(args.output).expanduser(), document)
    if args.ascii and not args.json:
        print()
        print(ascii_map(topology, width=78))

    counts = topology.counts()
    if args.json:
        _emit_json(
            {
                "site": topology.site,
                "generated_at": topology.generated_at,
                "fingerprint": topology.fingerprint,
                "digest": topology.digest,
                "counts": counts,
                "layers": [layer for layer in LAYERS if topology.nodes_in_layer(layer)],
                "scanners": [result.to_observation() for result in report.results],
                "warnings": topology.observations.get("warnings", []),
                "diff": diff.to_dict(),
                "recorded": bool(commit and commit.created),
                "seq": commit.entry.seq if commit else None,
                "unchanged": bool(commit and commit.unchanged),
                "changelog": str(changelog_path) if changelog_path else None,
                "notified": [
                    {"endpoint": item.endpoint, "ok": item.ok, "status": item.status, "error": item.error}
                    for item in notifications
                ],
                "output": str(args.output) if args.output else None,
            }
        )
        return EXIT_OK

    if not args.quiet:
        print()
    print(
        f"◈ {_count(counts['nodes'], 'node')} · {_count(counts['edges'], 'edge')} · "
        f"{len([layer for layer in LAYERS if topology.nodes_in_layer(layer)])}/4 layers"
    )
    print(f"  fingerprint {topology.fingerprint}")
    if commit is None:
        print("  ledger untouched (--no-save)")
    elif commit.created:
        print(f"  recorded #{commit.entry.seq} · sha256:{short_digest(commit.entry.digest)}")
    else:
        print(f"  unchanged · HEAD #{commit.entry.seq} · nothing to record")
    if previous is None:
        print("  first plat from this host; every observed node is new")
    elif diff.structural and not args.quiet:
        print()
        print(render_text(diff, verbose=False))
    if changelog_path:
        print()
        print(f"  changelog {changelog_path}")
    for item in notifications:
        if item.ok:
            print(f"  notified {item.endpoint} ({item.status})")
        else:
            print(f"  notification failed {item.endpoint}: {item.error}", file=sys.stderr)
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace) -> int:
    config = _config(args)
    ledger = Ledger(config.store)
    to_ref = args.to_ref or "HEAD"
    from_ref = args.from_ref or "HEAD~1"
    current, current_label = _parse_ref(to_ref, ledger)
    if current is None:
        raise StoreError("no survey available to compare; run `surveyor scan` first")
    previous, previous_label = _parse_ref(from_ref, ledger)

    report = diff_topologies(previous, current)
    if args.format == "json":
        _emit_json({**report.to_dict(), "from_label": previous_label, "to_label": current_label})
    elif args.format == "markdown":
        backend = "ollama" if args.polish else "template"
        output = compose_changelog(
            report, current, previous=previous, config=config, backend=backend
        )
        print(output.markdown)
    else:
        print(f"{current_label} vs {previous_label}")
        print(render_text(report, verbose=args.verbose))
        if previous is not None and previous.site != current.site:
            print(f"\n  note: site names differ ({previous.site!r} -> {current.site!r})")
    if args.exit_code and report.structural:
        return EXIT_CHANGED
    return EXIT_OK


def _cmd_log(args: argparse.Namespace) -> int:
    ledger = _resolve_ledger(args)
    entries = ledger.history(args.limit)
    if args.json:
        _emit_json([entry.to_dict() for entry in entries])
        return EXIT_OK
    if not entries:
        print(f"no surveys in {ledger.root}; run `surveyor scan`")
        return EXIT_OK
    print(f"{'seq':>4}  {'recorded':<20} {'plat':<14} {'nodes':>5} {'edges':>5}  note")
    for entry in entries:
        counts = entry.counts or {}
        print(
            f"{entry.seq:>4}  {entry.recorded_at:<20} {short_digest(entry.digest):<14} "
            f"{counts.get('nodes', 0):>5} {counts.get('edges', 0):>5}  {entry.note}"
        )
    head = ledger.head()
    if head:
        print(f"\nHEAD #{head.seq} · {head.digest} · fingerprint {head.fingerprint[:19]}")
    return EXIT_OK


def _cmd_history(args: argparse.Namespace) -> int:
    """What changed, and when it changed."""

    ledger = _resolve_ledger(args)
    changes = ledger.changes()
    if args.limit and args.limit > 0:
        changes = changes[-args.limit :]

    if not changes:
        if args.json:
            _emit_json([])
        else:
            print("no structural changes recorded; the map has not moved")
        return EXIT_OK

    if args.json:
        _emit_json(
            [
                {
                    "seq": entry.seq,
                    "recorded_at": entry.recorded_at,
                    "site": entry.site,
                    "digest": entry.digest,
                    "note": entry.note,
                    "narrative": _narrative_of(path),
                    "changelog": str(path),
                }
                for entry, path in changes
            ]
        )
        return EXIT_OK

    for entry, path in changes:
        narrative = _narrative_of(path)
        headline = narrative.splitlines()[0] if narrative else ""
        print(f"#{entry.seq} · {entry.recorded_at} · {headline}")
    return EXIT_OK


def _narrative_of(path: Path) -> str:
    """The opening paragraph of a changelog entry.

    The changelog is written as a heading, a provenance line, then the
    narrative, then the detail. The narrative is the part a reader wants
    when they are asking *what happened*.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    paragraphs: list[str] = []
    for block in text.split("\n\n"):
        stripped = block.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("**"):
            # The provenance line: site, digests, timestamp.
            continue
        paragraphs.append(stripped)
        break
    return paragraphs[0] if paragraphs else ""


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Say what this machine lets the Surveyor see."""

    from .doctor import examine, render

    config = _config(args)
    config_path = getattr(args, "config", "") or ""
    if not config_path:
        default = default_config_path()
        config_path = str(default) if default.exists() else ""

    report = examine(config, config_path=config_path)
    if args.json:
        _emit_json(report.to_dict())
        return EXIT_OK
    print(render(report))
    return EXIT_OK


def _cmd_show(args: argparse.Namespace) -> int:
    ledger = _resolve_ledger(args)
    topology, _label = _parse_ref(args.ref, ledger)
    if topology is None:
        print(f"no survey available at {args.ref}; run `surveyor scan`", file=sys.stderr)
        return EXIT_ERROR

    layers = [args.layer] if args.layer else []
    kinds = [args.kind] if args.kind else []
    tags = [args.tag] if args.tag else []
    if layers or kinds or tags:
        topology = topology.subgraph(layers=layers, kinds=kinds, tags=tags)
        if not topology.nodes:
            print("nothing in that plat matches the filter", file=sys.stderr)
            return EXIT_ERROR

    if args.format == "json":
        rendered = json.dumps(topology.to_dict(), indent=2, sort_keys=True)
    elif args.format == "markdown":
        rendered = markdown_table(topology)
    elif args.format == "mermaid":
        rendered = mermaid(topology)
    else:
        rendered = ascii_map(topology, width=78)

    if args.output:
        _write_text(Path(args.output).expanduser(), rendered)
        print(f"wrote {args.output}")
    else:
        print(rendered)
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    ledger = _resolve_ledger(args)
    report = ledger.verify()
    if args.json:
        _emit_json(report.to_dict())
    elif report.ok:
        print(f"✓ chain intact · {report.entries} entries · {report.objects} objects")
        print("  every object hashes to its name; every entry names its parent")
    else:
        print("✗ ledger verification failed", file=sys.stderr)
        for problem in report.problems:
            print(f"  - {problem}", file=sys.stderr)
    return EXIT_OK if report.ok else EXIT_ERROR


def _cmd_daemon(args: argparse.Namespace) -> int:
    config = _config(args)
    interval = args.interval or config.interval
    if not args.json_lines:
        print(f"◈ {format_daemon_start(config, interval=interval, once=args.once)}")
    stats = run_daemon(
        config,
        interval=interval,
        once=args.once,
        max_cycles=args.max_cycles,
        json_lines=args.json_lines,
    )
    if not args.json_lines:
        print(
            f"◈ stopped after {stats.cycles} cycle(s) · {stats.recorded} recorded · "
            f"{stats.unchanged} unchanged · {stats.structural_changes} structural change(s)"
        )
    return EXIT_OK


def _cmd_redact(args: argparse.Namespace) -> int:
    """Mask a plat's identifiers and report whatever survived."""

    from .redact import Aliaser, audit, masked_summary, redact_topology

    config = _config(args)
    ledger = Ledger(config.store)
    try:
        topology, label = _parse_ref(args.path, ledger)
    except StoreError:
        path = Path(args.path).expanduser()
        if not path.exists():
            raise
        topology = Topology.from_dict(json.loads(path.read_text(encoding="utf-8")))
        label = path.name
    if topology is None:
        raise StoreError(f"no survey available at {args.path}; run `surveyor scan` first")

    salt = ledger.salt
    aliaser = Aliaser(salt)
    redacted = redact_topology(topology, salt=salt)
    findings = audit(topology, redacted, aliaser)
    summary = masked_summary(topology, aliaser)

    if args.output:
        _write_text(Path(args.output).expanduser(), json.dumps(redacted.to_dict(), indent=2, sort_keys=True))
    elif not args.audit:
        print(json.dumps(redacted.to_dict(), indent=2, sort_keys=True))

    if args.audit:
        if args.json:
            _emit_json(
                {
                    "plat": label,
                    "masked": summary,
                    "keyed": bool(salt),
                    "findings": [finding.to_dict() for finding in findings],
                    "ok": not findings,
                }
            )
        else:
            print(f"◈ redaction audit · {label}")
            for category, count in sorted(summary.items()):
                print(f"  masked {category:<16} {count}")
            if not findings:
                print("  ✓ no identifier survived redaction")
            else:
                print(f"  ! {len(findings)} value(s) survived:")
                for finding in findings[:40]:
                    print(f"    - {finding.kind}: {finding.value!r} in {finding.where}")
                if len(findings) > 40:
                    print(f"    … {len(findings) - 40} more")
        if not args.output and args.json:
            return EXIT_OK if not findings else EXIT_ERROR
        return EXIT_OK if not findings else EXIT_ERROR

    if args.output:
        print(f"wrote {args.output}")
    return EXIT_OK


def _cmd_notify(args: argparse.Namespace) -> int:
    config = _config(args)
    if not config.notify:
        message = "no webhook configured: set notify = [...] in the config, pass --notify URL, "
        message += "or export SURVEYOR_NOTIFY"
        print(f"surveyor: {message}", file=sys.stderr)
        return EXIT_ERROR

    notifier = Notifier(
        config.notify,
        timeout=config.notify_timeout,
        format=config.notify_format,
        on=config.notify_on,
        dry_run=bool(args.dry_run),
    )

    if args.dry_run:
        payloads = {mask_url(url): sample_payload(url) for url in config.notify}
        if args.json:
            _emit_json(payloads)
        else:
            print(json.dumps(payloads, indent=2))
        return EXIT_OK

    results = notifier.ping()
    if args.json:
        _emit_json(
            [
                {
                    "endpoint": result.endpoint,
                    "ok": result.ok,
                    "status": result.status,
                    "error": result.error,
                    "attempts": result.attempts,
                }
                for result in results
            ]
        )
    else:
        for result in results:
            if result.ok:
                print(f"✓ {result.endpoint} delivered ({result.status})")
            else:
                print(f"✗ {result.endpoint} failed: {result.error}", file=sys.stderr)
    return EXIT_OK if all(result.ok for result in results) else EXIT_ERROR


def _cmd_export(args: argparse.Namespace) -> int:
    """Write a plat out as a document another ledger can read."""

    from .redact import redact_topology

    config = _config(args)
    ledger = Ledger(config.store)
    topology, _label = _parse_ref(args.ref, ledger)
    if topology is None:
        raise StoreError(f"no survey available at {args.ref}; run `surveyor scan` first")

    if args.redact:
        topology = redact_topology(topology, salt=ledger.salt)

    document = json.dumps(topology.to_dict(), indent=2, sort_keys=True)

    if args.repo:
        # A tree of plats, one file per site and host: the shape a
        # repository of infrastructure wants, so that "what changed on this
        # box" is a reviewable diff rather than a paste.
        root = Path(args.repo).expanduser()
        host = _host_of(topology) or "host"
        path = root / "plats" / slug(topology.site) / f"{slug(host)}.oet.json"
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document + "\n", encoding="utf-8")
        state = "unchanged" if previous.strip() == document.strip() else "changed"
        print(f"{state} · {path}")
        return EXIT_OK

    if args.output:
        _write_text(Path(args.output).expanduser(), document)
        print(f"wrote {args.output}")
    else:
        print(document)
    return EXIT_OK


def _cmd_import(args: argparse.Namespace) -> int:
    """Record a plat that came from another host."""

    from .validation import validate_document

    path = Path(args.path).expanduser()
    if not path.exists():
        raise SchemaError(f"{path} not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc

    problems = validate_document(data)
    if problems:
        for problem in problems:
            print(f"  - {problem.code}: {problem}", file=sys.stderr)
        raise SchemaError(f"{path} is not a valid OET document")

    topology = Topology.from_dict(data)
    host = args.host or _host_of(topology)
    if not host:
        raise SchemaError(
            "the document does not say which host it describes; pass --host"
        )

    config = _config(args)
    ledger = Ledger(config.store)
    result = ledger.commit_import(topology, host=host, note=args.note, force=args.force)

    if args.json:
        _emit_json(
            {
                "path": str(path),
                "host": host,
                "recorded": result.created,
                "unchanged": not result.created,
                "seq": result.entry.seq,
                "digest": result.entry.digest,
                "fingerprint": topology.fingerprint,
            }
        )
    elif result.created:
        print(f"◈ imported {host} · recorded #{result.entry.seq} · {result.entry.digest[:19]}")
        print(f"  {topology.counts()['nodes']} nodes · {topology.counts()['edges']} edges")
    else:
        print(f"◈ {host} unchanged · nothing to record")
    return EXIT_OK

def _host_of(topology: Topology) -> str:
    """The id of the host a plat describes."""

    for node in topology.nodes.values():
        if node.kind == "host":
            return node.id
    return ""


def _cmd_fleet(args: argparse.Namespace) -> int:
    """Compose every host in the ledger into one map."""

    from .fleet import compose, host_sites, summarise, tag_hosts

    config = _config(args)
    ledger = Ledger(config.store)
    plats = ledger.fleet_plats()
    if not plats:
        raise StoreError(f"no surveys in {ledger.root}; run `surveyor scan` first")

    if args.site:
        plats = [plat for plat in plats if plat.site == args.site]
        if not plats:
            raise StoreError(f"no surveys for site {args.site!r}")

    sites = host_sites(plats)
    composition = compose(plats, site=args.site or config.site)
    tag_hosts(composition.topology, sites)

    if args.json:
        _emit_json(summarise(composition, sites))
        return EXIT_OK

    if args.format == "json":
        rendered = json.dumps(composition.topology.to_dict(), indent=2, sort_keys=True)
    elif args.format == "markdown":
        rendered = markdown_table(composition.topology)
    elif args.format == "mermaid":
        rendered = mermaid(composition.topology)
    else:
        rendered = ascii_map(composition.topology, width=78)

    if args.output:
        _write_text(Path(args.output).expanduser(), rendered)
        print(f"wrote {args.output}")
    else:
        print(rendered)

    for conflict in composition.conflicts:
        print(f"  ! {conflict}", file=sys.stderr)
    for finding in composition.ambiguous:
        print(f"  ? {finding}", file=sys.stderr)
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    if not path.exists():
        raise SchemaError(f"{path} not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc

    problems = validate_document(data)
    counts: dict[str, Any] = {"nodes": 0, "edges": 0}
    fingerprint = str(data.get("fingerprint") or "")
    try:
        topology = Topology.from_dict(data)
    except SchemaError as exc:
        problems.append(Problem("bad-document", "", str(exc)))
    else:
        counts = topology.counts()
        if fingerprint and fingerprint != topology.fingerprint:
            problems.append(
                Problem(
                    "fingerprint-mismatch",
                    "fingerprint",
                    f"declared {fingerprint[:19]} does not match the document "
                    f"({topology.fingerprint[:19]})",
                )
            )
        elif not fingerprint:
            fingerprint = topology.fingerprint

    if args.json:
        _emit_json(
            {
                "path": str(path),
                "ok": not problems,
                "oet_version": str(data.get("oet_version") or ""),
                "fingerprint": fingerprint,
                "counts": counts,
                "problems": [problem.to_dict() for problem in problems],
            }
        )
    else:
        status = "✓ valid" if not problems else "✗ invalid"
        print(f"{status} · {path}")
        print(
            f"  OET {data.get('oet_version', '')} · {data.get('site', '')} · "
            f"{data.get('generated_at', '')}"
        )
        print(f"  {counts['nodes']} nodes · {counts['edges']} edges · fingerprint {fingerprint}")
        for problem in problems:
            print(f"  - {problem.code}: {problem}", file=sys.stderr)
    return EXIT_OK if not problems else EXIT_ERROR


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(args, "handler", _cmd_root)
    try:
        return int(handler(args))
    except SurveyorError as exc:
        print(f"surveyor: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("surveyor: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["BANNER", "SHORT", "build_parser", "default_store", "main"]
