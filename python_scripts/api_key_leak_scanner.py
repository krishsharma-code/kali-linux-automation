#!/usr/bin/env python3
"""Scan a directory tree for hardcoded secrets and credentials.

The scanner walks a workspace, matches the contents of every text file against
a set of well-known credential signatures (generic API keys, Google API keys,
AWS access keys, Slack tokens and GitHub personal access tokens), and reports
each hit. It is intended to run locally and as a lightweight CI gate before
code is committed or pushed.

Exit codes:
    0 - scan completed and no potential secrets were found
    1 - scan completed and at least one potential secret was found
    2 - the scan could not run (for example, the target path does not exist)

Safety note:
    Matched secret material is never echoed to the console. Only a redacted
    context snippet is printed, so scanner output can be pasted into CI logs or
    bug reports without re-leaking the very credential it detected.
"""

import argparse
import os
import re
import sys
from pathlib import Path

# --- Configuration ----------------------------------------------------------

# Directories that never hold first-party source and are expensive or pointless
# to walk (VCS metadata, virtual environments, caches, vendored dependencies).
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "__pycache__", "node_modules",
}

# Binary and archive extensions that must not be read as text.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".tiff",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".7z", ".rar", ".pdf",
}

# Files larger than this are skipped: they are almost never source code and
# reading them would waste memory. Keeps the scanner's footprint bounded.
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB

# Named credential signatures. The *last* capturing group of each pattern is
# treated as the secret value so it can be redacted before anything is printed.
SECRET_PATTERNS = {
    "Generic API Key": re.compile(
        r"(?i)(api[_-]?key|apikey|auth[_-]?token|access[_-]?token)"
        r"[\s:=]+['\"]([a-zA-Z0-9]{16,})['\"]"
    ),
    "Google API Key": re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
    "AWS Access Key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "Slack Token": re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,48})"),
    "GitHub Personal Access Token": re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
}

REDACTION_MARKER = "***REDACTED***"


def _secret_span(match):
    """Return the ``(start, end)`` offsets of the secret inside ``match``.

    The secret is the last non-empty capturing group, or the whole match when
    the pattern defines no capturing groups.
    """
    for index in range(match.re.groups, 0, -1):
        if match.group(index) is not None:
            return match.start(index), match.end(index)
    return match.start(0), match.end(0)


def mask_line(line, match):
    """Return ``line`` with the matched secret replaced by a fixed marker.

    The surrounding context is preserved so a reviewer can locate the leak, but
    the credential itself is never part of the returned string.
    """
    start, end = _secret_span(match)
    redacted = f"{line[:start]}{REDACTION_MARKER}{line[end:]}"
    return redacted.strip()


def _looks_binary(path):
    """Return True when the first block of ``path`` contains a NUL byte."""
    try:
        with path.open("rb") as probe:
            return b"\x00" in probe.read(1024)
    except OSError:
        # If we cannot even read the header, let the text pass below report it.
        return False


def scan_file(path):
    """Scan a single file and return a list of finding dictionaries.

    Each finding is ``{"name", "path", "line", "snippet"}`` where ``snippet``
    is redacted. Binary files, oversized files and unreadable files return an
    empty list instead of raising, so one bad file cannot abort a whole scan.

    Args:
        path: A :class:`pathlib.Path` to a regular file.

    Returns:
        A list of finding dictionaries (possibly empty).
    """
    findings = []
    path = Path(path)
    try:
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return findings

        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            print(f"[!] Skipping large file ({size} bytes): {path}")
            return findings

        if _looks_binary(path):
            return findings

        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_no, line in enumerate(handle, start=1):
                for name, pattern in SECRET_PATTERNS.items():
                    for match in pattern.finditer(line):
                        findings.append({
                            "name": name,
                            "path": str(path),
                            "line": line_no,
                            "snippet": mask_line(line, match),
                        })
    except OSError as exc:
        print(f"[!] Could not read {path}: {exc}")
    return findings


def scan_directory(directory):
    """Recursively scan ``directory`` and return every finding.

    Skipped directories are pruned in place so :func:`os.walk` never descends
    into them.

    Args:
        directory: Root directory to walk (str or :class:`pathlib.Path`).

    Returns:
        A flat list of finding dictionaries across all scanned files.
    """
    root = Path(directory)
    findings = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            findings.extend(scan_file(Path(current) / name))
    return findings


def report(findings):
    """Print a human-readable report for ``findings``."""
    for finding in findings:
        print(f"[!] LEAK DETECTED [{finding['name']}] "
              f"{finding['path']}:{finding['line']}")
        print(f"    {finding['snippet']}")
    if not findings:
        print("[+] No hardcoded API keys or secrets detected.")
    else:
        print(f"[*] Scan complete. {len(findings)} potential leaks found.")


def main(argv=None):
    """Parse arguments, run the scan and return a process exit code."""
    parser = argparse.ArgumentParser(
        description="Scan a directory tree for hardcoded API keys and secrets.")
    parser.add_argument(
        "directory", nargs="?", default=".",
        help="directory to scan (default: current directory)")
    args = parser.parse_args(argv)

    target = Path(args.directory)
    print("=== API Key Leak Scanner ===")
    print(f"[*] Scanning directory: {target}")

    if not target.is_dir():
        print(f"[-] Error: {target} is not a directory.")
        return 2

    findings = scan_directory(target)
    report(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
