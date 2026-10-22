# Security

## Posture

The Surveyor is a **read-only observer**. It does not configure, restart,
install, or delete anything on the machine it surveys. It writes only inside its
own ledger directory (`~/.surveyor` by default, or `--store`).

That promise is enforced in code, not just documented:

- **Command allowlist.** `probe.ALLOWED_PROGRAMS` names every executable the
  scanners may run (`sysctl`, `pmset`, `ioreg`, `ifconfig`, `ip`, `route`,
  `lsof`, `ss`, `docker ps`, `sw_vers`, `uname`, …). Shells, `sudo`, and
  scripting bridges are rejected before a process is created.
- **No shell.** Commands are argument vectors passed with `shell=False`.
- **Scrubbed environment.** Variables whose names contain `TOKEN`, `SECRET`,
  `PASSWORD`, `API_KEY`, `CREDENTIAL`, or `SESSION` are removed from child
  processes, so a survey cannot leak credentials into logs or subprocesses.
- **Bounded execution.** Every probe has a timeout, output is capped at 2 MB,
  and each scanner runs inside a total time budget.

## Data handling

A plat can contain hostnames, MAC addresses, serial numbers, IP addresses,
interface names, container images, and the names of local models and listening
processes. Treat an unredacted plat as **internal** data.

Use `--redact` (or `redact = true`) before publishing a plat. Redaction masks
MAC host bits, aliases serials and SSIDs with SHA-256 prefixes, and truncates
public IPv4 addresses. Private addresses are preserved because the map is
useless without them; review the output before publishing anyway.

Ledger objects are stored unencrypted. Protect the directory with filesystem
permissions; the bundled systemd unit runs as an unprivileged user with a
read-only view of the rest of the system.

## Optional local model

`scribe = "ollama"` sends the diff's *facts* and the deterministic draft to the
configured endpoint (loopback by default) so a local model can rewrite the
opening paragraph. No other data leaves the machine, and the deterministic
changelog is written even when the model is unavailable. Pointing
`ollama_endpoint` at a remote host is an explicit operator choice and should be
treated as data egress.

## Reporting

Open a private security advisory on the repository, or email the maintainer
listed in `pyproject.toml`. Please include the version (`surveyor --version`),
the platform, and the smallest reproduction you can manage. Do not attach a real
unredacted plat.
