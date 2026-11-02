#!/usr/bin/env python3
"""Generate a UFW block script from a list of untrusted IP addresses.

A "malicious IP" feed is attacker-influenced data: the addresses in it come
from whoever is attacking the host, so a hostile feed entry is one of the
cheapest ways to attack the defender. The first version of this tool
interpolated every line of the feed straight into a shell script, so a line
such as

    198.51.100.7; id

became a command that the operator's shell ran with root privileges the
moment the generated script was executed. This version parses each entry with
:mod:`ipaddress` before anything is written and emits only the canonical
address string, so no shell metacharacter can reach the output file.

The tool never changes firewall state itself. It writes a reviewable script
(atomically, with owner-only permissions) and the operator decides whether to
run it. Malformed lines are reported and skipped rather than silently dropped.

Exit codes:
    0 - a block script was generated (with ``--dry-run``: rules were printed)
    1 - the input held no valid entries, so nothing was written
    2 - the tool could not run (missing input, unwritable output, bad arguments)

Usage:
    python3 malicious_ip_blocker.py --input bad_ips.txt --output apply_blocks.sh
    python3 malicious_ip_blocker.py --input bad_ips.txt --dry-run
    python3 malicious_ip_blocker.py --demo
"""

import argparse
import ipaddress
import os
import shlex
import sys
import tempfile
from pathlib import Path

DEFAULT_OUTPUT = "apply_blocks.sh"

# Sample addresses used by --demo. All three are documentation/private ranges,
# so running the demo can never touch a real third party.
DEFAULT_DEMO_ENTRIES = ("192.168.1.100", "203.0.113.10", "45.33.32.156")

# Any legitimate IPv6 CIDR is far shorter than this. The cap keeps a single
# absurd line from being parsed, echoed or written at all.
MAX_ENTRY_CHARS = 128


class BlocklistError(Exception):
    """Raised when the block list or the output location cannot be used."""


def _comment_safe(text):
    """Return ``text`` flattened to a single printable line.

    Used when a value (such as a file name) is echoed into the generated
    script's header comment. A newline in the value would otherwise end the
    comment and turn the remainder into a live shell command.
    """
    cleaned = "".join(char if char.isprintable() else " " for char in str(text))
    return cleaned.strip()[:200] or "unknown"


def parse_ip_entry(raw):
    """Return the canonical form of one block-list entry, or ``None``.

    Args:
        raw: A single line from the block list. It may carry a trailing
            ``#`` comment and surrounding whitespace.

    Returns:
        The canonical address string (``203.0.113.10``, ``2001:db8::1``,
        ``10.0.0.0/8``), or ``None`` when the entry is blank, too long or not
        an address or network. Only canonical strings are ever returned, so
        the caller can write them into a shell script safely.
    """
    entry = raw.split("#", 1)[0].strip()
    if not entry or len(entry) > MAX_ENTRY_CHARS:
        return None
    try:
        if "/" in entry:
            # strict=False so a host address with a prefix ("10.1.2.3/8") is
            # accepted and normalised to its network instead of rejected.
            return str(ipaddress.ip_network(entry, strict=False))
        return str(ipaddress.ip_address(entry))
    except ValueError:
        # ipaddress rejects anything that is not a bare address or network,
        # including shell metacharacters, host names and out-of-range octets.
        return None


def load_blocklist(path):
    """Read ``path`` and return ``(accepted, rejected)``.

    Args:
        path: File holding one address or CIDR per line. Blank lines and
            ``#`` comments are ignored.

    Returns:
        A tuple ``(accepted, rejected)``. ``accepted`` is a de-duplicated list
        of canonical entries in first-seen order. ``rejected`` is a list of
        ``(line_number, raw_line)`` pairs so the operator can fix the feed.

    Raises:
        BlocklistError: The file is missing, unreadable or is a directory.
    """
    source = Path(path)
    try:
        # errors="replace" so a feed with a stray non-UTF-8 byte still loads;
        # the affected line then simply fails validation.
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise BlocklistError(f"cannot read {source}: {exc}") from exc

    accepted = []
    rejected = []
    seen = set()
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        parsed = parse_ip_entry(raw)
        if parsed is None:
            rejected.append((line_number, raw.strip()))
            continue
        if parsed in seen:
            continue
        seen.add(parsed)
        accepted.append(parsed)
    return accepted, rejected


def render_block_script(entries, source_name="block list"):
    """Return the text of a UFW script that denies traffic from ``entries``.

    Args:
        entries: Canonical address strings, as returned by
            :func:`load_blocklist`. They are written verbatim, so they must
            already be validated.
        source_name: Human-readable origin of the list, recorded in the
            header comment for the reviewer's benefit.

    Returns:
        The complete script as a string, ending in a newline.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# shellcheck shell=bash",
        "# Generated by malicious_ip_blocker.py - review before running.",
        f"# Source: {_comment_safe(source_name)}",
        "# Every address below was validated with Python's ipaddress module;",
        "# no other content from the source list is reproduced here.",
        "set -euo pipefail",
        "",
    ]
    if not entries:
        lines.append("echo 'No block rules to apply.'")
        return "\n".join(lines) + "\n"

    for entry in entries:
        lines.append(f"sudo ufw deny from {entry} to any")
    lines.append("")
    lines.append(f"echo 'Applied {len(entries)} UFW block rule(s).'")
    return "\n".join(lines) + "\n"


def write_block_script(output_path, content):
    """Write ``content`` to ``output_path`` atomically, with 0600 permissions.

    The file is staged in a temporary file beside the target and renamed into
    place, so an interrupted run can never leave a half-written rule script
    that looks complete. It is deliberately *not* marked executable: making
    the operator pass it to ``bash`` explicitly keeps a human in the loop.

    Args:
        output_path: Destination file. Its parent directory must exist.
        content: Full script text.

    Returns:
        The resolved :class:`~pathlib.Path` of the written file.

    Raises:
        BlocklistError: The directory is missing or the write failed.
    """
    target = Path(output_path)
    directory = target.parent if str(target.parent) else Path(".")
    if not directory.is_dir():
        raise BlocklistError(f"output directory {directory} does not exist")

    staged = None
    try:
        handle_fd, staged = tempfile.mkstemp(
            dir=str(directory), prefix=".blocklist-", suffix=".tmp")
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staged, 0o600)
        os.replace(staged, target)
    except OSError as exc:
        if staged and os.path.exists(staged):
            os.unlink(staged)
        raise BlocklistError(f"cannot write {target}: {exc}") from exc
    return target.resolve()


def generate_block_script(input_path, output_path=DEFAULT_OUTPUT, dry_run=False):
    """Validate a block list and (unless ``dry_run``) write the UFW script.

    Args:
        input_path: File holding the addresses to block.
        output_path: Where to write the generated script.
        dry_run: When true, render the script but write nothing.

    Returns:
        A summary dict with the keys ``accepted`` (list of canonical
        addresses), ``rejected`` (list of ``(line, raw)`` pairs), ``text``
        (the rendered script), ``output`` (written :class:`~pathlib.Path` or
        ``None``) and ``written`` (bool). ``written`` is false for a dry run
        and also when the input held no valid entries.

    Raises:
        BlocklistError: The input cannot be read or the output cannot be
            written.
    """
    accepted, rejected = load_blocklist(input_path)
    summary = {
        "accepted": accepted,
        "rejected": rejected,
        "text": render_block_script(accepted, Path(input_path).resolve()),
        "output": None,
        "written": False,
    }
    if not accepted or dry_run:
        return summary

    summary["output"] = write_block_script(output_path, summary["text"])
    summary["written"] = True
    return summary


def _run(input_path, output_path, dry_run):
    """Execute one generation run and return a process exit code."""
    try:
        summary = generate_block_script(input_path, output_path, dry_run=dry_run)
    except BlocklistError as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 2

    for line_number, raw in summary["rejected"]:
        print(f"[!] Skipped line {line_number}: not an IP address or CIDR: {raw!r}")

    if not summary["accepted"]:
        print("[-] No valid entries in the list; nothing was written.",
              file=sys.stderr)
        return 1

    if dry_run:
        print(f"[*] Dry run: {len(summary['accepted'])} rule(s), no file written.")
        print(summary["text"])
        return 0

    for entry in summary["accepted"]:
        print(f"  [+] Block: {entry}")
    print(f"[SUCCESS] Wrote {len(summary['accepted'])} rule(s) to "
          f"{summary['output']}")
    print(f"[INFO] Review it, then apply with: sudo bash "
          f"{shlex.quote(str(summary['output']))}")
    return 0


def _run_demo(dry_run):
    """Run against a sample list inside a throwaway directory.

    The earlier version of this script always wrote its sample list and output
    into the current directory, overwriting any real files of the same name.
    The demo now works entirely inside a temporary directory.
    """
    with tempfile.TemporaryDirectory(prefix="ip-blocker-demo-") as workdir:
        sample = Path(workdir) / "malicious_ips.txt"
        sample.write_text("\n".join(DEFAULT_DEMO_ENTRIES) + "\n",
                          encoding="utf-8")
        print(f"[*] Demo workspace: {workdir}")
        return _run(sample, Path(workdir) / DEFAULT_OUTPUT, dry_run)


def main(argv=None):
    """Parse arguments, generate the script and return a process exit code."""
    parser = argparse.ArgumentParser(
        description="Generate a UFW block script from a list of untrusted "
                    "IP addresses. Nothing is applied; the script is written "
                    "for review.")
    parser.add_argument("-i", "--input",
                        help="file holding one IP address or CIDR per line")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"script to write (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the rules instead of writing a file")
    parser.add_argument("--demo", action="store_true",
                        help="run against a sample list in a temporary "
                             "directory and leave the working tree alone")
    args = parser.parse_args(argv)

    print("=== Malicious IP Blocker ===")

    # argparse handles --help before this point, so the help path performs no
    # filesystem work at all.
    if args.demo:
        return _run_demo(args.dry_run)

    if not args.input:
        parser.print_usage(sys.stderr)
        print("[-] Error: --input is required (or pass --demo).",
              file=sys.stderr)
        return 2

    return _run(args.input, args.output, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
