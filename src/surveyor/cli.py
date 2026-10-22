"""Command line interface for The Surveyor.

Every command is read-only with respect to the surveyed machine. Writes are
confined to the ledger directory (``~/.surveyor/ledger`` by default) and to
files the operator names explicitly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import OET_VERSION, __version__
from .ascii import BANNER, LEGEND, SHORT, TAGLINE, banner, supports_color
from .compiler import survey
from .config import Config, ConfigError, default_config_path, default_store
from .daemon import format_daemon_start, run_daemon
from .differ import diff_topologies, render_text
from .errors import SchemaError, StoreError, SurveyorError
from .model import LAYERS, Topology
from .render import ascii_map, markdown_table, mermaid
from .scanners.base import registry
from .scribe import compose_changelog
from .store import Ledger
from .util import short_digest

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

    show = subparsers.add_parser("show", parents=[common], help="print a recorded plat")
    show.add_argument("ref", nargs="?", default="HEAD", help="seq, digest prefix, or file (default HEAD)")
    show.add_argument("--format", choices=("ascii", "markdown", "mermaid", "json"), default="ascii")
    show.add_argument("--output", "--out", dest="output", help="write to a file instead of stdout")
    show.set_defaults(handler=_cmd_show)

    verify = subparsers.add_parser("verify", parents=[common], help="verify ledger integrity and hash chain")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=_cmd_verify)

    daemon = subparsers.add_parser("daemon", parents=[common], help="survey on a schedule")
    daemon.add_argument("--interval", type=int, default=None, help="seconds between surveys")
    daemon.add_argument("--once", action="store_true", help="run a single cycle")
    daemon.add_argument("--max-cycles", type=int, default=None, help="stop after N cycles")
    daemon.add_argument("--json-lines", action="store_true", help="emit one JSON object per cycle")
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
        entry = entries[-1]
        return ledger.get(entry.digest), f"#{entry.seq}"
    if ref == "HEAD~1":
        if len(entries) < 2:
            return None, "before the first survey"
        entry = entries[-2]
        return ledger.get(entry.digest), f"#{entry.seq}"
    if ref.isdigit():
        entry = ledger.entry_at(int(ref))
        return ledger.get(entry.digest), f"#{entry.seq}"

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
    color = _color(args)
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
                "output": str(args.output) if args.output else None,
            }
        )
        return EXIT_OK

    if not args.quiet:
        print()
    print(
        f"◈ {counts['nodes']} nodes · {counts['edges']} edges · "
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
        print("  first plat for this ledger; every observed node is new")
    elif diff.structural and not args.quiet:
        print()
        print(render_text(diff, verbose=False))
    if changelog_path:
        print()
        print(f"  changelog {changelog_path}")
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


def _cmd_show(args: argparse.Namespace) -> int:
    ledger = _resolve_ledger(args)
    topology, _label = _parse_ref(args.ref, ledger)
    if topology is None:
        print(f"no survey available at {args.ref}; run `surveyor scan`", file=sys.stderr)
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
    else:
        if report.ok:
            print(f"✓ chain intact · {report.entries} entries · {report.objects} objects")
            print(f"  every object hashes to its name; every entry names its parent")
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


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    if not path.exists():
        raise SchemaError(f"{path} not found")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    topology = Topology.from_dict(data)
    dangling = topology.dangling_edges()
    problems = [f"dangling edge {edge.id}" for edge in dangling]
    declared = str(data.get("fingerprint") or "")
    if declared and declared != topology.fingerprint:
        problems.append(
            f"declared fingerprint {declared[:19]} does not match the document "
            f"({topology.fingerprint[:19]})"
        )
    counts = topology.counts()
    if args.json:
        _emit_json(
            {
                "path": str(path),
                "ok": not problems,
                "oet_version": topology.schema_version,
                "fingerprint": topology.fingerprint,
                "counts": counts,
                "problems": problems,
            }
        )
    else:
        status = "✓ valid" if not problems else "✗ invalid"
        print(f"{status} · {path}")
        print(f"  OET {topology.schema_version} · {topology.site} · {topology.generated_at}")
        print(f"  {counts['nodes']} nodes · {counts['edges']} edges · fingerprint {topology.fingerprint}")
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
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


__all__ = ["main", "build_parser", "BANNER", "SHORT", "default_store"]
