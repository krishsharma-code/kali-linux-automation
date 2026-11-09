#!/usr/bin/env python3
"""Audit the permissions, ownership and file type of a shadow password file.

``/etc/shadow`` holds the password hashes for every local account, so any
relaxation of its metadata is a direct credential-exposure risk: a
world-readable shadow file lets any local user take the hashes offline and
crack them, and a world-writable one lets them plant a known hash for root.

This script only *stats* the file, so it never reads a single hash and does
**not** need to run as root -- ``stat(2)`` on ``/etc/shadow`` succeeds for any
user who can traverse ``/etc``. Reading the file's contents would require root,
but that is not something an integrity audit should do.

Checks performed, all on the ``lstat`` result so a symlink cannot redirect the
audit at an attacker-controlled file:

* the path is a regular file and not a symbolic link;
* no world read, world write or group write bit is set;
* no setuid, setgid or sticky bit is set (``0o7777`` is masked, not just
  ``0o0777``, so a ``0o4600`` shadow file is reported instead of passing);
* the owner is root (UID 0) and the group is root or shadow (GID 0 or 42).

Exit codes, so the script is usable from cron and CI:

* ``0`` -- no finding at or above ``--fail-on`` (default: ``high``)
* ``1`` -- at least one finding at or above ``--fail-on``
* ``2`` -- the path could not be inspected at all

Examples:
    python3 shadow_file_integrity.py
    python3 shadow_file_integrity.py --json
    python3 shadow_file_integrity.py --path ./fixtures/shadow --fail-on low
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_SHADOW_PATH = Path("/etc/shadow")

#: Root must own the shadow file.
EXPECTED_OWNER_UID = 0

#: Debian/Ubuntu ship ``root:shadow`` (GID 42); RHEL/Fedora ship ``root:root``.
ACCEPTED_GROUP_GIDS = frozenset({0, 42})

#: Ordered from most to least severe; used for filtering and for sorting output.
SEVERITIES = ("critical", "high", "medium", "low", "info")

#: Findings at or above this severity make the script exit non-zero.
DEFAULT_FAIL_ON = "high"


@dataclass(frozen=True)
class Finding:
    """One problem detected while auditing the shadow file.

    Attributes:
        code: Stable machine-readable identifier, e.g. ``SHADOW_WORLD_READABLE``.
        severity: One of :data:`SEVERITIES`.
        message: Human-readable description of the risk and its impact.
    """

    code: str
    severity: str
    message: str

    def as_dict(self) -> dict:
        """Return the finding as a plain dictionary for JSON output."""
        return asdict(self)


def severity_rank(severity: str) -> int:
    """Return the position of *severity* in :data:`SEVERITIES` (0 is worst).

    Args:
        severity: A severity name such as ``"high"``.

    Returns:
        The index of *severity*, or ``len(SEVERITIES)`` when it is unknown, so
        an unexpected value is treated as the least severe rather than raising.
    """
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return len(SEVERITIES)


def _permission_findings(mode: int) -> list[Finding]:
    """Map a permission bitmask to the findings it implies.

    Args:
        mode: The ``st_mode`` value from ``lstat``; special bits are inspected
            as well as the low nine permission bits.

    Returns:
        A list of findings, possibly empty.
    """
    perms = stat.S_IMODE(mode)
    findings: list[Finding] = []

    if perms & stat.S_IROTH:
        findings.append(
            Finding(
                "SHADOW_WORLD_READABLE",
                "critical",
                f"Shadow file is world-readable ({oct(perms)}); every local user can read "
                "the password hashes and crack them offline.",
            )
        )
    if perms & stat.S_IWOTH:
        findings.append(
            Finding(
                "SHADOW_WORLD_WRITABLE",
                "critical",
                f"Shadow file is world-writable ({oct(perms)}); any local user can replace "
                "the root password hash.",
            )
        )
    if perms & stat.S_IWGRP:
        findings.append(
            Finding(
                "SHADOW_GROUP_WRITABLE",
                "high",
                f"Shadow file is group-writable ({oct(perms)}); every member of the owning "
                "group can replace password hashes.",
            )
        )
    if perms & stat.S_IRGRP:
        findings.append(
            Finding(
                "SHADOW_GROUP_READABLE",
                "info",
                f"Shadow file is group-readable ({oct(perms)}); this is expected on "
                "root:shadow 640 systems, but 600 is stricter.",
            )
        )
    if perms & stat.S_ISUID:
        findings.append(
            Finding(
                "SHADOW_SETUID",
                "critical",
                f"Shadow file has the setuid bit set ({oct(perms)}); it should never be "
                "executable, let alone privileged.",
            )
        )
    if perms & stat.S_ISGID:
        findings.append(
            Finding(
                "SHADOW_SETGID",
                "high",
                f"Shadow file has the setgid bit set ({oct(perms)}); it should never be "
                "executable.",
            )
        )
    if perms & stat.S_ISVTX:
        findings.append(
            Finding(
                "SHADOW_STICKY",
                "medium",
                f"Shadow file has the sticky bit set ({oct(perms)}); that bit has no "
                "meaning on a regular file.",
            )
        )
    return findings


def audit(
    path: os.PathLike | str = DEFAULT_SHADOW_PATH,
    expected_uid: int = EXPECTED_OWNER_UID,
    accepted_gids: Iterable[int] = ACCEPTED_GROUP_GIDS,
) -> list[Finding]:
    """Audit one shadow file and return every finding, most severe first.

    ``lstat`` is used deliberately: following a symlink would let an attacker
    point the audit at a file they control and report a clean result for the
    real ``/etc/shadow``.

    Args:
        path: Path to the shadow file. Defaults to ``/etc/shadow``.
        expected_uid: UID that must own the file. Defaults to root (0).
        accepted_gids: Group IDs that may own the file. Defaults to root and
            shadow.

    Returns:
        Findings sorted by severity. An empty list means the file passed every
        check.

    Raises:
        FileNotFoundError: The path does not exist.
        PermissionError: The path cannot be stat'ed (a parent directory is not
            traversable).
        OSError: Any other stat failure.
    """
    file_path = Path(path)
    st = os.lstat(file_path)
    findings: list[Finding] = []

    if stat.S_ISLNK(st.st_mode):
        # Report and stop: the mode/owner bits below describe the link, not the
        # target, so continuing would produce misleading "all clear" output.
        return [
            Finding(
                "SHADOW_SYMLINK",
                "critical",
                f"{file_path} is a symbolic link; the real shadow file must be a regular "
                "file, so the audit cannot vouch for its permissions.",
            )
        ]
    if not stat.S_ISREG(st.st_mode):
        return [
            Finding(
                "SHADOW_NOT_REGULAR_FILE",
                "critical",
                f"{file_path} is not a regular file; refusing to treat it as the shadow "
                "database.",
            )
        ]

    findings.extend(_permission_findings(st.st_mode))

    if st.st_uid != expected_uid:
        findings.append(
            Finding(
                "SHADOW_BAD_OWNER",
                "critical",
                f"Shadow file is owned by UID {st.st_uid}, expected UID {expected_uid}.",
            )
        )

    allowed_gids = frozenset(accepted_gids)
    if st.st_gid not in allowed_gids:
        findings.append(
            Finding(
                "SHADOW_BAD_GROUP",
                "medium",
                f"Shadow file is owned by GID {st.st_gid}, expected one of "
                f"{sorted(allowed_gids)} (root or shadow).",
            )
        )

    findings.sort(key=lambda finding: severity_rank(finding.severity))
    return findings


def remediation_hint(path: Path, findings: Sequence[Finding]) -> str:
    """Build a ``chmod``/``chown`` hint that matches the findings actually seen.

    The advice is derived from the findings so the script never recommends a
    blanket ``chown root:root`` on a distro that legitimately uses
    ``root:shadow``.

    Args:
        path: The audited path, used in the suggested command.
        findings: The findings produced by :func:`audit`.

    Returns:
        A one-line remediation suggestion, or an empty string when nothing
        actionable was found.
    """
    codes = {finding.code for finding in findings}
    if not codes:
        return ""

    target_gid = 0 if "SHADOW_BAD_GROUP" in codes else 42
    group = "shadow" if target_gid == 42 else "root"
    return (
        f"chmod 600 {path} && chown root:{group} {path} "
        "(use 'shadow' only on systems where that group exists)"
    )


def report_text(path: Path, findings: Sequence[Finding], hint: str) -> str:
    """Render the human-readable audit report.

    Args:
        path: The audited path.
        findings: Findings from :func:`audit`.
        hint: Remediation line from :func:`remediation_hint`.

    Returns:
        The report as a newline-terminated string.
    """
    lines = ["=== Shadow File Integrity Audit ===", f"[*] Target: {path}"]

    if not findings:
        lines.append("[+] Permissions and ownership meet security standards.")
        return "\n".join(lines) + "\n"

    lines.append(f"[!] {len(findings)} finding(s):")
    for finding in findings:
        lines.append(f"    [{finding.severity.upper()}] {finding.code}: {finding.message}")
    if hint:
        lines.append(f"[*] Recommendation: {hint}")
    return "\n".join(lines) + "\n"


def report_json(path: Path, findings: Sequence[Finding], hint: str) -> str:
    """Render the audit report as a single JSON document.

    Args:
        path: The audited path.
        findings: Findings from :func:`audit`.
        hint: Remediation line from :func:`remediation_hint`.

    Returns:
        Pretty-printed JSON, newline-terminated.
    """
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    payload = {
        "path": str(path),
        "ok": not findings,
        "counts": counts,
        "findings": [finding.as_dict() for finding in findings],
        "remediation": hint or None,
    }
    return json.dumps(payload, indent=2) + "\n"


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Audit the permissions and ownership of a shadow password file.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 inspection error.",
    )
    parser.add_argument(
        "--path",
        default=str(DEFAULT_SHADOW_PATH),
        help=f"shadow file to audit (default: {DEFAULT_SHADOW_PATH})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "none"),
        default=DEFAULT_FAIL_ON,
        help=f"lowest severity that makes the exit code non-zero (default: {DEFAULT_FAIL_ON})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing; rely on the exit code",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit from the command line.

    Args:
        argv: Argument list, defaulting to ``sys.argv[1:]``.

    Returns:
        The process exit code documented in the module docstring.
    """
    args = build_parser().parse_args(argv)
    path = Path(args.path)

    try:
        findings = audit(path)
    except FileNotFoundError:
        print(f"[!] {path} not found. Are you on a Linux system?", file=sys.stderr)
        return 2
    except PermissionError:
        print(
            f"[!] Cannot inspect {path}: permission denied on a parent directory.",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"[!] Cannot inspect {path}: {exc}", file=sys.stderr)
        return 2

    hint = remediation_hint(path, findings)

    if not args.quiet:
        render = report_json if args.json else report_text
        sys.stdout.write(render(path, findings, hint))

    if args.fail_on == "none" or not findings:
        return 0

    threshold = severity_rank(args.fail_on)
    return 1 if any(severity_rank(f.severity) <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
