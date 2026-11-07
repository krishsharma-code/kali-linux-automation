#!/usr/bin/env bash
#
# file_integrity_monitor.sh - Cron-friendly SHA-256 baseline and verification of
# critical system files.
#
# Day 9: Forensics and Hardening
#
# What it does
#   First run: records a SHA-256 baseline of the critical files that exist on
#   this host into a state file owned by the invoking user (mode 0600).
#   Later runs: recomputes each hash and reports any file that is MODIFIED,
#   MISSING or UNREADABLE, exiting non-zero so cron, CI or a wrapper can alert.
#
# Security notes
#   * The baseline used to live at the predictable path /tmp/sys_file_hashes.db,
#     which any local user can pre-create or symlink: a root cron job appending
#     to a symlink writes wherever the attacker points it, and a forged baseline
#     silently disables the monitor. The state file now defaults to a directory
#     owned by the caller and mode 0700/0600, and a symlinked database is
#     refused outright.
#   * The baseline is written to a temporary file and renamed into place, so an
#     interrupted run can never leave a half-written baseline behind.
#   * Files that exist but cannot be read (typically /etc/shadow without root)
#     are reported instead of being hashed as if they were empty. A baseline
#     with a silent hole in it is worse than no baseline, so this is an error
#     unless --allow-partial is given.
#   * Verification parses the baseline itself instead of shelling out to
#     `sha256sum -c`, so a modified file, a deleted file and an unreadable file
#     are reported distinctly and each file is hashed exactly once.
#
# Exit codes
#   0  baseline created, or every recorded file matched
#   1  at least one file was MODIFIED or MISSING
#   2  usage error, or the baseline could not be written/read (including
#      unreadable critical files without --allow-partial)
#
# Usage
#   sudo ./file_integrity_monitor.sh            # verify, creating a baseline if absent
#   sudo ./file_integrity_monitor.sh --init     # rebuild the baseline
#   ./file_integrity_monitor.sh --files "/etc/passwd /etc/hosts" --db ./hashes.db
#   ./file_integrity_monitor.sh --help

set -uo pipefail

# Everything this script creates is private to the invoking user: the baseline
# is a map of the exact bytes of /etc/shadow, so it must not be world-readable.
umask 077

readonly SCRIPT_NAME="${0##*/}"

# The files worth watching on a stock Debian/Kali host. Override with --files.
readonly DEFAULT_FILES=(
    /etc/passwd
    /etc/shadow
    /etc/sudoers
    /usr/bin/ssh
)

MODE="verify"
FILES_SPEC=""
DB_PATH="${FIM_DB:-}"
STATE_DIR="${FIM_STATE_DIR:-}"
ALLOW_PARTIAL=0
# An explicit --db may point anywhere the caller can write; only the default
# per-user state directory gets the strict ownership and mode checks.
STRICT_DIR=1
[[ -n "$DB_PATH" ]] && STRICT_DIR=0

log_info() { printf '[*] %s\n' "$*"; }
log_ok()   { printf '[+] %s\n' "$*"; }
log_warn() { printf '[!] %s\n' "$*" >&2; }
log_err()  { printf '[-] %s\n' "$*" >&2; }

# Usage and setup problems share exit code 2, so a caller can tell "the monitor
# could not run" apart from "the monitor ran and something changed" (1).
die() {
    log_err "$*"
    exit 2
}

usage() {
    cat <<EOF
$SCRIPT_NAME - SHA-256 baseline and verification for critical system files

Usage:
  $SCRIPT_NAME [options]

Modes:
  (default)          Verify the recorded files, creating a baseline if none exists
  -i, --init         Rebuild the baseline from the current state of the files

Options:
  -f, --files LIST   Files to monitor, space-separated (or one per line when a
                     path contains a space)
                     (default: ${DEFAULT_FILES[*]})
  -d, --db PATH      Baseline file to use
                     (default: \$XDG_STATE_HOME/file-integrity-monitor/hashes.db)
      --state-dir D  Directory for the default baseline file
      --allow-partial
                     Record the readable files and continue when a critical file
                     cannot be read, instead of failing
  -h, --help         Show this help and exit without touching anything

Environment:
  FIM_DB, FIM_STATE_DIR   Same as --db and --state-dir
  XDG_STATE_HOME, HOME    Used to pick the default state directory

Exit codes:
  0  baseline created, or all recorded files matched
  1  a file was modified or is missing
  2  usage error, or the baseline could not be written or read
EOF
}

while (($#)); do
    case "$1" in
        -h|--help)     usage; exit 0 ;;
        -i|--init)     MODE="init"; shift ;;
        -f|--files)    [[ $# -ge 2 ]] || die "--files requires an argument"; FILES_SPEC="$2"; shift 2 ;;
        -d|--db)       [[ $# -ge 2 ]] || die "--db requires an argument"; DB_PATH="$2"; STRICT_DIR=0; shift 2 ;;
        --state-dir)   [[ $# -ge 2 ]] || die "--state-dir requires an argument"; STATE_DIR="$2"; shift 2 ;;
        --allow-partial) ALLOW_PARTIAL=1; shift ;;
        *)             die "unknown option: $1 (try --help)" ;;
    esac
done

# Resolve the state directory. A per-user XDG location is the safe default; the
# old shared /tmp path is deliberately not used any more.
if [[ -z "$STATE_DIR" ]]; then
    if [[ -n "${XDG_STATE_HOME:-}" ]]; then
        STATE_DIR="$XDG_STATE_HOME/file-integrity-monitor"
    elif [[ -n "${HOME:-}" ]]; then
        STATE_DIR="$HOME/.local/state/file-integrity-monitor"
    else
        STATE_DIR="/var/lib/file-integrity-monitor"
    fi
fi
[[ -n "$DB_PATH" ]] || DB_PATH="$STATE_DIR/hashes.db"

# Split the file list. The original interface was space-separated, which makes a
# path containing a space impossible to express; a multi-line list is therefore
# honoured as one path per line, and the space-separated form still works.
FILES=()
if [[ "$FILES_SPEC" == *$'\n'* ]]; then
    while IFS= read -r entry; do
        [[ -n "$entry" ]] && FILES+=("$entry")
    done <<<"$FILES_SPEC"
else
    read -r -a FILES <<<"${FILES_SPEC:-${DEFAULT_FILES[*]}}"
fi
(( ${#FILES[@]} )) || die "no files to monitor"

command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found in PATH"

# --------------------------------------------------------------------------
# State directory handling
# --------------------------------------------------------------------------

# Create a directory if needed and check that it is safe to write a baseline
# into. The default state directory must be owned by the invoking user and mode
# 0700: a directory another local user can write is a directory in which the
# baseline can be replaced. An explicit --db only needs a writable parent.
prepare_dir() {
    local dir="$1" strict="$2" owner mode perm

    [[ -L "$dir" ]] && die "refusing to use a symlinked directory: $dir"

    if [[ ! -d "$dir" ]]; then
        mkdir -p -- "$dir" || die "cannot create directory: $dir"
    fi

    if (( strict )); then
        owner="$(stat -c '%u' -- "$dir" 2>/dev/null)" || die "cannot stat directory: $dir"
        [[ "$owner" == "$EUID" ]] || die "state directory $dir is owned by uid $owner, not $EUID"

        mode="$(stat -c '%a' -- "$dir" 2>/dev/null)" || die "cannot stat directory: $dir"
        # Compare only the rwx bits; setgid on a shared parent is harmless.
        perm="${mode: -3}"
        if [[ "$perm" != "700" ]]; then
            log_warn "state directory $dir is mode $perm, tightening to 700"
            chmod 700 -- "$dir" || die "cannot restrict permissions on $dir"
        fi
    else
        [[ -w "$dir" ]] || die "cannot write to $dir"
    fi
}

# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

# Write the baseline atomically: build it in a private temporary file inside the
# same directory, then rename it over the old one. A crash mid-write leaves the
# previous baseline intact rather than a truncated one.
write_baseline() {
    local db="$1" tmp digest path count=0 skipped=0 unreadable=0

    prepare_dir "$(dirname -- "$db")" "$STRICT_DIR"

    [[ -L "$db" ]] && die "refusing to write a baseline through a symlink: $db"

    tmp="$(mktemp "$(dirname -- "$db")/.hashes.XXXXXX")" || die "cannot create a temporary file next to $db"
    # shellcheck disable=SC2064  # expand $tmp now, on purpose
    trap "rm -f -- '$tmp'" EXIT

    log_info "Initializing Hash Database: $db"

    for path in "${FILES[@]}"; do
        if [[ ! -e "$path" ]]; then
            log_warn "not present on this host, skipping: $path"
            skipped=$((skipped + 1))
            continue
        fi
        if [[ ! -f "$path" ]]; then
            log_warn "not a regular file, skipping: $path"
            skipped=$((skipped + 1))
            continue
        fi
        if [[ ! -r "$path" ]]; then
            log_warn "cannot read $path (run with sudo for full coverage)"
            unreadable=$((unreadable + 1))
            continue
        fi

        # Take only the digest: sha256sum escapes paths containing backslashes
        # and newlines, which would corrupt a baseline we parse ourselves.
        digest="$(sha256sum -- "$path" 2>/dev/null)" || {
            log_warn "hashing failed: $path"
            unreadable=$((unreadable + 1))
            continue
        }
        printf '%s  %s\n' "${digest%% *}" "$path" >>"$tmp" || die "cannot write $tmp"
        count=$((count + 1))
    done

    if (( count == 0 )); then
        die "no readable files to record; refusing to write an empty baseline"
    fi

    if (( unreadable > 0 )) && (( ALLOW_PARTIAL == 0 )); then
        die "$unreadable file(s) could not be read; rerun with sudo or pass --allow-partial"
    fi

    chmod 600 -- "$tmp" || die "cannot restrict permissions on $tmp"
    mv -f -- "$tmp" "$db" || die "cannot move baseline into place: $db"
    trap - EXIT

    log_ok "Baseline written: $count file(s) recorded, $skipped not present"
}

# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

# Compare each recorded file against its hash. One pass, one hash per file, and
# a distinct message per failure mode so the operator knows whether a file
# changed, vanished, or simply became unreadable.
verify_baseline() {
    local db="$1" line expected path actual violations=0 unreadable=0 checked=0

    [[ -f "$db" ]] || die "baseline not found: $db"

    log_info "Starting Integrity Verification against $db"

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue

        # Baseline format is "<sha256><two spaces><path>"; the two-space
        # separator is what makes paths containing single spaces safe.
        expected="${line%%  *}"
        path="${line#*  }"
        [[ "$expected" =~ ^[0-9a-f]{64}$ && -n "$path" ]] || {
            log_warn "ignoring malformed baseline line: $line"
            continue
        }

        if [[ ! -e "$path" ]]; then
            log_err "[ALERT] MISSING: $path"
            violations=$((violations + 1))
            continue
        fi
        if [[ ! -r "$path" ]]; then
            log_warn "UNREADABLE: $path (run with sudo to compare it)"
            unreadable=$((unreadable + 1))
            continue
        fi

        actual="$(sha256sum -- "$path" 2>/dev/null)" || {
            log_warn "hashing failed: $path"
            unreadable=$((unreadable + 1))
            continue
        }
        actual="${actual%% *}"
        checked=$((checked + 1))

        if [[ "$actual" != "$expected" ]]; then
            log_err "[ALERT] MODIFIED: $path"
            log_err "        expected $expected"
            log_err "        actual   $actual"
            violations=$((violations + 1))
        fi
    done <"$db"

    if (( violations > 0 )); then
        log_err "[ALERT] Integrity Violation Detected! $violations file(s) changed; check /var/log/syslog."
        return 1
    fi
    if (( unreadable > 0 )); then
        log_warn "$unreadable file(s) could not be checked; integrity is unconfirmed."
        return 2
    fi
    if (( checked == 0 )); then
        log_warn "baseline recorded no verifiable files"
        return 2
    fi

    log_ok "[OK] All critical files are intact."
    return 0
}

if [[ "$MODE" == "init" ]]; then
    write_baseline "$DB_PATH"
    exit 0
fi

if [[ ! -f "$DB_PATH" ]]; then
    # First run: there is nothing to compare against yet, so record a baseline
    # instead of reporting a vacuous success.
    write_baseline "$DB_PATH"
    exit 0
fi

verify_baseline "$DB_PATH"
exit $?
