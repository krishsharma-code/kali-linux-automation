#!/usr/bin/env python3
"""Parse an ``auth.log`` and rank source IPs by failed SSH authentication count.

The script reads a Linux authentication log (``/var/log/auth.log`` on Debian
and Kali, ``/var/log/secure`` on RHEL) and counts failed SSH password
authentications per source address, so an operator can see which hosts are
being brute-forced. It understands both the OpenSSH ``sshd`` line format and
the PAM ``authentication failure`` format emitted by ``login``/``sudo``.

Threat model
------------
Log lines are attacker-influenced: an unauthenticated remote user chooses the
username they try, and therefore part of every line written here. The parser
is written accordingly:

* Source addresses are parsed with :mod:`ipaddress` and **only** a valid IPv4
  or IPv6 literal is ever stored, counted or printed. A crafted username such
  as ``\\x1b[2Jroot`` can never reach the terminal, so the report cannot be
  turned into a terminal-escape injection.
* The per-address table is bounded by ``MAX_TRACKED_ADDRESSES``; a log padded
  with millions of distinct addresses cannot exhaust memory. Addresses past
  the cap are counted in a single overflow bucket.
* Individual lines longer than ``MAX_LINE_CHARS`` are truncated before
  matching, and files are opened with ``errors="replace"`` so a malformed or
  partly binary log degrades instead of aborting the run.

Exit codes:
    0 - the log was parsed and no address reached the alert threshold
    1 - the log was parsed and at least one address reached the threshold
    2 - the log could not be read (missing file, permission denied, not a file)

Usage:
    python3 auth_log_parser.py --log /var/log/auth.log
    python3 auth_log_parser.py --log /var/log/auth.log --threshold 3 --top 10
    python3 auth_log_parser.py --demo          # parse a generated sample log
"""

import argparse
import ipaddress
import re
import sys
from pathlib import Path

# --- Configuration ----------------------------------------------------------

# Addresses seen at least this many times are reported as CRITICAL rather than
# WARNING. Overridable with --threshold.
DEFAULT_THRESHOLD = 5

# Hard ceiling on the number of distinct source addresses held in memory. Each
# entry is small, but the key is attacker-chosen, so the table must be bounded
# or a log flooded with spoofed sources becomes a memory-exhaustion vector.
MAX_TRACKED_ADDRESSES = 10_000

# Log lines are matched, not stored, so only the head of an over-long line can
# matter. Truncating keeps peak memory per line constant even if a single line
# is gigabytes wide.
MAX_LINE_CHARS = 8_192

# OpenSSH:  "Failed password for root from 192.168.1.50 port 22 ssh2"
#           "Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
# The address is taken as the token after "from"; validity is checked later.
SSHD_FAILURE_PATTERN = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?\S+ from (\S+)"
)

# PAM:      "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.9"
PAM_FAILURE_PATTERN = re.compile(r"authentication failure;.*\brhost=(\S+)")

# --- Parsing helpers --------------------------------------------------------


def normalise_address(token):
    """Return the canonical text form of an IP literal, or ``None``.

    Args:
        token: A whitespace-delimited token taken from an untrusted log line.

    Returns:
        The normalised address string (for example ``"::1"`` or
        ``"192.168.1.50"``), or ``None`` when ``token`` is not a bare IP
        literal. Ports, hostnames, ``rhost=``-style values with trailing
        punctuation and control sequences are all rejected.
    """
    if not token:
        return None
    candidate = token.strip().strip(",;")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    # sshd on a dual-stack socket logs IPv4 peers as "::ffff:192.168.1.50".
    # Collapsing them to the plain IPv4 form keeps one attacker from being
    # counted twice (once per representation) and keeps the report readable.
    if address.version == 6 and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)

    return str(address)


def classify_line(line):
    """Return the source address that a failed-authentication line blames.

    Args:
        line: One raw line from the log file.

    Returns:
        A normalised address string, or ``None`` when the line is not a
        failed-authentication record or carries no usable address.
    """
    match = SSHD_FAILURE_PATTERN.search(line)
    if match:
        return normalise_address(match.group(1))

    match = PAM_FAILURE_PATTERN.search(line)
    if match:
        return normalise_address(match.group(1))

    return None


def iter_log_lines(log_path):
    """Yield lines from ``log_path``, tolerating undecodable bytes.

    The file is opened once and streamed, so memory use is independent of the
    log's size. Undecodable bytes are replaced rather than raising
    :class:`UnicodeDecodeError`, which is what an attacker-influenced or
    partially rotated log would otherwise trigger.

    Args:
        log_path: Path to the log file.

    Yields:
        Lines, truncated to ``MAX_LINE_CHARS``.

    Raises:
        OSError: If the file cannot be opened or read.
    """
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line[:MAX_LINE_CHARS]


def count_failed_attempts(log_path, max_addresses=MAX_TRACKED_ADDRESSES):
    """Count failed authentications per source address.

    Args:
        log_path: Path to the log file.
        max_addresses: Maximum number of distinct addresses to track. Further
            addresses are counted in a single overflow tally instead, so
            memory stays bounded on a flooded log.

    Returns:
        A ``(counts, overflow)`` tuple. ``counts`` maps address to attempt
        count; ``overflow`` is the number of attempts whose address did not
        fit in the table.

    Raises:
        OSError: If the log cannot be read.
    """
    counts = {}
    overflow = 0

    for line in iter_log_lines(log_path):
        address = classify_line(line)
        if address is None:
            continue
        if address in counts:
            counts[address] += 1
        elif len(counts) < max_addresses:
            counts[address] = 1
        else:
            overflow += 1

    return counts, overflow


def rank_attempts(counts, top=None):
    """Order addresses by attempt count, highest first.

    Args:
        counts: Mapping of address to attempt count.
        top: When given, only this many entries are returned.

    Returns:
        A list of ``(address, count)`` tuples. Ties break on address text so
        the output is stable between runs.
    """
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked[:top] if top else ranked


# --- Reporting --------------------------------------------------------------

def report(counts, overflow, threshold=DEFAULT_THRESHOLD, top=None, out=None):
    """Print the suspicious-activity report.

    Every address printed here came through :func:`normalise_address`, so the
    output contains no attacker-supplied text beyond a validated IP literal.

    Args:
        counts: Mapping of address to attempt count.
        overflow: Attempts that did not fit in the tracking table.
        threshold: Attempt count at or above which an address is CRITICAL.
        top: When given, only this many addresses are printed.
        out: Stream to write to (defaults to ``sys.stdout``).

    Returns:
        The number of addresses reported at or above ``threshold``.
    """
    out = out or sys.stdout
    ranked = rank_attempts(counts, top)

    print("\n[!] SUSPICIOUS ACTIVITY REPORT", file=out)
    print("-" * 30, file=out)

    if not ranked:
        print("[*] No failed authentication attempts matched.", file=out)

    critical = 0
    for address, count in ranked:
        status = "CRITICAL" if count >= threshold else "WARNING"
        if count >= threshold:
            critical += 1
        print(f"[{status}] IP: {address} | Failed Attempts: {count}", file=out)

    if overflow:
        print(
            f"[!] {overflow} attempt(s) came from untracked addresses beyond the "
            f"{MAX_TRACKED_ADDRESSES}-address cap.",
            file=out,
        )

    return critical


# --- Demo data --------------------------------------------------------------

DEMO_LOG_LINES = [
    "May 28 10:00:01 kali sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2\n",
    "May 28 10:01:05 kali sshd[1235]: Failed password for admin from 192.168.1.50 port 22 ssh2\n",
    "May 28 10:02:10 kali sshd[1236]: Accepted password for user1 from 192.168.1.10 port 22 ssh2\n",
    "May 28 10:05:15 kali sshd[1237]: Failed password for root from 203.0.113.5 port 22 ssh2\n",
    "May 28 10:06:20 kali sshd[1238]: Failed password for invalid user oracle from 203.0.113.5 port 22 ssh2\n",
    "May 28 10:07:00 kali login[1239]: authentication failure; logname= uid=0 euid=0 tty=ssh rhost=198.51.100.7\n",
    "May 28 10:08:20 kali sshd[1240]: Failed password for root from 192.168.1.50 port 22 ssh2\n",
]


def write_demo_log(log_path, lines=None):
    """Write a synthetic ``auth.log`` for demonstrations.

    The file is only written when it does not already exist, so running the
    demo cannot silently clobber a real log the operator happens to have in the
    working directory.

    Args:
        log_path: Destination path.
        lines: Lines to write (defaults to :data:`DEMO_LOG_LINES`).

    Returns:
        The path written, as a :class:`pathlib.Path`.

    Raises:
        FileExistsError: If ``log_path`` already exists.
    """
    path = Path(log_path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    path.write_text("".join(lines if lines is not None else DEMO_LOG_LINES), encoding="utf-8")
    return path


# --- Entry point ------------------------------------------------------------

def parse_auth_log(log_path, threshold=DEFAULT_THRESHOLD, top=None, out=None):
    """Parse ``log_path``, print the report and return the per-address counts.

    Args:
        log_path: Path to the log file.
        threshold: Attempt count at or above which an address is CRITICAL.
        top: When given, only this many addresses are printed.
        out: Stream to write to (defaults to ``sys.stdout``).

    Returns:
        A mapping of address to failed-attempt count, or ``None`` when the log
        could not be read.
    """
    out = out or sys.stdout
    path = Path(log_path)

    try:
        print(f"[*] Analyzing Log: {path}", file=out)
        counts, overflow = count_failed_attempts(path)
    except OSError as error:
        # One handled path for missing files, permission errors, directories and
        # mid-read failures - no exists()-then-open() race in between.
        print(f"[-] Error: cannot read log {path}: {error}", file=out)
        return None

    report(counts, overflow, threshold=threshold, top=top, out=out)
    return counts


def build_parser():
    """Build the command-line argument parser.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description="Count failed SSH authentications per source address in an auth.log.",
    )
    parser.add_argument(
        "--log", "-l", default="/var/log/auth.log",
        help="path to the authentication log (default: %(default)s)",
    )
    parser.add_argument(
        "--threshold", "-t", type=int, default=DEFAULT_THRESHOLD,
        help="attempts at or above which an address is CRITICAL (default: %(default)s)",
    )
    parser.add_argument(
        "--top", "-n", type=int, default=None,
        help="only report the N busiest addresses (default: all)",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="write a sample auth.log to the current directory and parse it",
    )
    return parser


def main(argv=None):
    """Run the CLI.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 clean, 1 threshold reached, 2 log unreadable.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be >= 1")
    if args.top is not None and args.top < 1:
        parser.error("--top must be >= 1")

    log_path = args.log
    if args.demo:
        try:
            log_path = write_demo_log("mock_auth.log")
        except FileExistsError as error:
            print(f"[!] {error}; parsing the existing file instead.")

    counts = parse_auth_log(log_path, threshold=args.threshold, top=args.top)
    if counts is None:
        return 2

    critical = sum(1 for count in counts.values() if count >= args.threshold)
    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
