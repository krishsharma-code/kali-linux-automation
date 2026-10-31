#!/usr/bin/env python3
"""Audit running systemd services for unit files in unexpected locations.

A unit file that lives outside the standard systemd directories (or inside a
world-writable directory such as ``/tmp``) is a classic persistence trick: an
attacker who can drop a service file there gets their payload restarted on
every boot. This script enumerates the services that are running *right now*
and reports the ones whose ``FragmentPath`` looks wrong.

How it works
------------
1. ``systemctl list-units --type=service --state=running`` gives the service
   names.  ``--plain`` is passed so the output has no bullet/colour markers and
   can be parsed reliably.
2. For each name, ``systemctl show <unit> --property=FragmentPath`` gives the
   unit file that systemd actually loaded.
3. The path is resolved (symlinks followed) and compared *by path component*
   against the standard directories.  Component comparison matters: a naive
   ``str.startswith("/lib/systemd/system")`` would happily accept
   ``/lib/systemd/system-evil/backdoor.service``.

Trust boundary
--------------
Everything printed by ``systemctl`` is treated as untrusted input.  Unit names
are validated against a conservative character class before they are handed
back to a subprocess, every ``systemctl`` call is bounded by a timeout, and a
failure to query one unit is recorded and reported instead of being silently
swallowed.

Exit codes
----------
0   No non-standard or high-risk unit files were found.
1   At least one non-standard or high-risk unit file was found.
2   The audit could not run (systemctl missing, timed out, or failed).

Usage
-----
    python3 systemd_service_auditor.py
    python3 systemd_service_auditor.py --json
    python3 systemd_service_auditor.py --standard-path /opt/systemd/system
    python3 systemd_service_auditor.py --no-resolve-symlinks --timeout 5

Requires systemd on the host; the script itself makes no state changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field

SYSTEMCTL = "systemctl"

#: Directories a distribution ships unit files in.  Override with
#: ``--standard-path`` when auditing a system that keeps units elsewhere.
DEFAULT_STANDARD_DIRS: tuple[str, ...] = (
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/systemd/system",
)

#: Directories that are writable by non-root users or are wiped on reboot.
HIGH_RISK_DIRS: tuple[str, ...] = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
)

#: Default per-call timeout for a ``systemctl`` invocation, in seconds.
DEFAULT_TIMEOUT = 15.0

#: Unit names systemd accepts: alphanumerics plus ``: _ . @ -`` and the
#: ``\x2d``-style escapes some units use.  Anything else is not passed on to a
#: subprocess.
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:\\-]+$")

SEVERITY_HIGH = "high"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"


class AuditError(RuntimeError):
    """Raised when the audit cannot produce a trustworthy result.

    Used for conditions that make the whole run meaningless (systemctl absent,
    timing out, or exiting non-zero) rather than for a single bad unit, which
    is recorded in :attr:`AuditReport.errors` and does not abort the scan.
    """


@dataclass(frozen=True)
class Finding:
    """One suspicious (or merely noteworthy) service unit file."""

    service: str
    fragment_path: str
    reason: str
    severity: str


@dataclass
class AuditReport:
    """Result of a single audit run."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    services_checked: int = 0

    @property
    def has_problems(self) -> bool:
        """True when a finding warrants a non-zero exit code."""
        return any(f.severity in (SEVERITY_HIGH, SEVERITY_WARNING) for f in self.findings)


# ---------------------------------------------------------------------------
# systemctl helpers
# ---------------------------------------------------------------------------

def _run_systemctl(args: list[str], timeout: float = DEFAULT_TIMEOUT) -> str:
    """Run ``systemctl <args>`` and return its stdout.

    ``args`` is always a list, so no shell is involved and unit names cannot be
    interpreted as shell syntax.  Raises :class:`AuditError` if systemctl is
    missing, exceeds ``timeout``, or exits non-zero.
    """
    try:
        completed = subprocess.run(
            [SYSTEMCTL, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AuditError("systemctl not found; is systemd installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise AuditError(
            f"systemctl {args[0] if args else ''} timed out after {timeout}s"
        ) from exc
    except OSError as exc:  # e.g. permission denied on the binary
        raise AuditError(f"could not execute systemctl: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AuditError(
            f"systemctl {' '.join(args)} exited {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout


def list_running_services(timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Return the names of currently running service units.

    Blank lines, the ``●`` bullet some systemd versions emit, and names that do
    not match :data:`SERVICE_NAME_RE` are dropped rather than forwarded to a
    second subprocess.
    """
    output = _run_systemctl(
        ["list-units", "--type=service", "--state=running", "--no-legend", "--plain"],
        timeout=timeout,
    )

    services: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("\u25cf\u2022* ").strip()
        if not line:
            continue
        name = line.split()[0]
        if SERVICE_NAME_RE.match(name):
            services.append(name)
    return services


def get_fragment_path(service: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Return the ``FragmentPath`` systemd reports for ``service``.

    Returns ``None`` when the property is present but empty, which is normal
    for transient units that have no unit file on disk.
    """
    if not SERVICE_NAME_RE.match(service):
        raise ValueError(f"refusing to query malformed unit name: {service!r}")

    output = _run_systemctl(
        ["show", service, "--property=FragmentPath"], timeout=timeout
    )
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "FragmentPath":
            return value.strip() or None
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _is_within(path: str, directory: str) -> bool:
    """True when ``path`` is ``directory`` itself or sits beneath it.

    Comparison is done on normalised path components, so ``/tmp-evil`` is not
    considered to be inside ``/tmp`` and ``/lib/systemd/system-evil`` is not
    considered to be a standard systemd directory.
    """
    path = os.path.normpath(path)
    directory = os.path.normpath(directory)
    return path == directory or path.startswith(directory + os.sep)


def classify_path(
    service: str,
    fragment_path: str | None,
    standard_dirs: tuple[str, ...] = DEFAULT_STANDARD_DIRS,
    high_risk_dirs: tuple[str, ...] = HIGH_RISK_DIRS,
    resolve_symlinks: bool = True,
) -> Finding | None:
    """Classify one unit file location, returning a :class:`Finding` or ``None``.

    Symlinks are resolved first: ``/etc/systemd/system/foo.service`` is very
    often a symlink to ``/lib/systemd/system/foo.service`` and is perfectly
    normal, so flagging it would be a false positive.
    """
    if not fragment_path:
        return Finding(service, "", "missing-fragment-path", SEVERITY_INFO)

    path = os.path.realpath(fragment_path) if resolve_symlinks else fragment_path
    path = os.path.normpath(path)

    if any(_is_within(path, d) for d in high_risk_dirs):
        return Finding(service, fragment_path, "high-risk-path", SEVERITY_HIGH)

    if not any(_is_within(path, d) for d in standard_dirs):
        return Finding(service, fragment_path, "non-standard-path", SEVERITY_WARNING)

    return None


def audit_services(
    standard_dirs: tuple[str, ...] = DEFAULT_STANDARD_DIRS,
    high_risk_dirs: tuple[str, ...] = HIGH_RISK_DIRS,
    timeout: float = DEFAULT_TIMEOUT,
    resolve_symlinks: bool = True,
) -> AuditReport:
    """Audit every running service and return the findings.

    A failure while querying a single unit is appended to
    :attr:`AuditReport.errors` and the scan continues, so one unreadable unit
    cannot mask the rest of the report.  Raises :class:`AuditError` if the unit
    list itself cannot be retrieved.
    """
    report = AuditReport()
    services = list_running_services(timeout=timeout)
    report.services_checked = len(services)

    for service in services:
        try:
            fragment_path = get_fragment_path(service, timeout=timeout)
        except (AuditError, ValueError) as exc:
            report.errors.append(f"{service}: {exc}")
            continue

        finding = classify_path(
            service,
            fragment_path,
            standard_dirs=standard_dirs,
            high_risk_dirs=high_risk_dirs,
            resolve_symlinks=resolve_symlinks,
        )
        if finding is not None:
            report.findings.append(finding)

    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(report: AuditReport) -> None:
    """Print a human-readable report in the tool's traditional format."""
    for finding in report.findings:
        if finding.reason == "high-risk-path":
            print(f"[!] NON-STANDARD PATH: {finding.service} -> {finding.fragment_path}")
            print(f"    [!] HIGH RISK: Service {finding.service} is running from {finding.fragment_path}")
        elif finding.reason == "non-standard-path":
            print(f"[!] NON-STANDARD PATH: {finding.service} -> {finding.fragment_path}")
        else:  # missing-fragment-path - informational only
            print(f"[*] NO UNIT FILE: {finding.service} has no FragmentPath (transient unit?)")

    for error in report.errors:
        print(f"[!] Could not inspect {error}")

    non_standard = sum(1 for f in report.findings if f.severity != SEVERITY_INFO)
    if non_standard == 0:
        print("[+] All active systemd services are running from standard locations.")
    else:
        print(f"[*] Audit complete. {non_standard} non-standard services found.")


def report_to_dict(report: AuditReport) -> dict:
    """Serialise a report for ``--json`` consumers."""
    return {
        "services_checked": report.services_checked,
        "findings": [asdict(f) for f in report.findings],
        "errors": report.errors,
        "has_problems": report.has_problems,
    }


def audit_systemd_services() -> AuditReport:
    """Run the default audit and print it.

    Kept as the historical entry point so ``from systemd_service_auditor
    import audit_systemd_services`` keeps working; prefer :func:`audit_services`
    when you want the data without the printing.
    """
    print("=== Systemd Service Auditor ===")
    print("[*] Listing active services and checking for non-standard paths...")

    try:
        report = audit_services()
    except AuditError as exc:
        print(f"[!] Error running systemctl: {exc}")
        return AuditReport(errors=[str(exc)])

    print_report(report)
    return report


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.  Returns the process exit code."""
    parser = argparse.ArgumentParser(
        description="Flag running systemd services whose unit files live outside standard locations.",
    )
    parser.add_argument(
        "--standard-path",
        dest="standard_paths",
        action="append",
        metavar="DIR",
        help="treat DIR as a standard unit directory (repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-systemctl-call timeout (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    parser.add_argument(
        "--no-resolve-symlinks",
        action="store_true",
        help="classify the raw FragmentPath without resolving symlinks",
    )
    args = parser.parse_args(argv)

    standard_dirs = tuple(args.standard_paths) if args.standard_paths else DEFAULT_STANDARD_DIRS

    try:
        report = audit_services(
            standard_dirs=standard_dirs,
            timeout=args.timeout,
            resolve_symlinks=not args.no_resolve_symlinks,
        )
    except AuditError as exc:
        print(f"[!] Error running systemctl: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print_report(report)

    return 1 if report.has_problems else 0


if __name__ == "__main__":
    sys.exit(main())
