#!/usr/bin/env bash
#
# backup_critical_configs.sh - Create a verified, owner-only backup archive of
# critical system configuration files.
#
# Day 5: Security Auditing & System Defense
#
# What it does
#   1. Selects the critical files that actually exist on this host.
#   2. Packs them into a single gzip'd tar archive inside a directory that is
#      restricted to the invoking user (mode 0700), with the archive itself at
#      mode 0600 - /etc/shadow must never land in a world-readable location.
#   3. Verifies the archive before it is published (gzip integrity + entry
#      count), then renames it into place atomically and writes a SHA-256
#      sidecar file next to it.
#   4. Prunes old archives, keeping the most recent N.
#
# Security notes
#   * Files that exist but cannot be read (for example /etc/shadow without
#     root) are a hard error: silently producing a "successful" backup that is
#     missing the password database is worse than failing.
#   * The archive is built under a temporary name and only renamed after it has
#     been verified, so a partially written file is never mistaken for a good
#     backup.
#   * Every state-changing action is printed before it happens, and --dry-run
#     prints the whole plan without touching the filesystem.
#
# Restoring: tar stores members with the leading slash stripped, so extract an
# archive from / with `sudo tar -xzf <archive> -C /` after checking it against
# the .sha256 sidecar.
#
# Exit codes
#   0  success
#   1  usage error
#   2  a source file could not be read, or no readable sources were found
#   3  the archive failed verification
#   4  the archive could not be written
#
# Usage
#   sudo ./backup_critical_configs.sh
#   ./backup_critical_configs.sh --dry-run
#   ./backup_critical_configs.sh --backup-dir /var/backups/configs --keep 10

set -euo pipefail

# Restrict the default permissions of everything this script creates. Combined
# with the explicit chmod calls below this keeps /etc/shadow out of reach of
# other local users.
umask 077

readonly SCRIPT_NAME="${0##*/}"
readonly DEFAULT_BACKUP_DIR="/tmp/security_backups"
readonly DEFAULT_FILES="/etc/passwd /etc/group /etc/shadow /etc/ssh/sshd_config /etc/network/interfaces /etc/hosts"
readonly ARCHIVE_PREFIX="critical_configs_"

BACKUP_DIR="${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}"
FILES_SPEC="${BACKUP_FILES:-$DEFAULT_FILES}"
KEEP=5
DRY_RUN=0
ALLOW_PARTIAL=0
TMP_ARCHIVE=""

# --------------------------------------------------------------------------
# Output helpers. Informational lines go to stdout, problems to stderr, so the
# script stays usable in a pipeline or cron job that mails stdout.
# --------------------------------------------------------------------------
log_info() { printf '[*] %s\n' "$*"; }
log_ok()   { printf '[+] %s\n' "$*"; }
log_warn() { printf '[!] %s\n' "$*" >&2; }
log_err()  { printf '[-] %s\n' "$*" >&2; }

usage() {
    cat <<EOF
$SCRIPT_NAME - back up critical system configuration files

Usage:
  $SCRIPT_NAME [options]

Options:
  -d, --backup-dir DIR   Directory to write the archive into
                         (default: $DEFAULT_BACKUP_DIR, env BACKUP_DIR)
  -f, --files "F1 F2"    Space-separated list of files to back up
                         (env BACKUP_FILES)
  -k, --keep N           Keep the N most recent archives, 0 keeps all
                         (default: 5)
  -p, --allow-partial    Warn instead of failing when a source file is present
                         but unreadable
  -n, --dry-run          Print the plan without writing anything
  -h, --help             Show this help and exit

Exit codes: 0 success, 1 usage, 2 unreadable/missing sources,
            3 verification failure, 4 write failure.

Run with sudo when the file list includes /etc/shadow.
EOF
}

die() {
    local code=$1
    shift
    log_err "$*"
    exit "$code"
}

# --------------------------------------------------------------------------
# Argument parsing. Kept manual so the script has no dependency on getopt and
# behaves identically on every host the toolkit supports.
# --------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d|--backup-dir)
                [ $# -ge 2 ] || die 1 "$1 requires a directory argument"
                BACKUP_DIR="$2"
                shift 2
                ;;
            -f|--files)
                [ $# -ge 2 ] || die 1 "$1 requires a space-separated file list"
                FILES_SPEC="$2"
                shift 2
                ;;
            -k|--keep)
                [ $# -ge 2 ] || die 1 "$1 requires a number"
                case "$2" in
                    ''|*[!0-9]*) die 1 "--keep expects a non-negative integer, got '$2'" ;;
                esac
                KEEP="$2"
                shift 2
                ;;
            -p|--allow-partial)
                ALLOW_PARTIAL=1
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                die 1 "unknown option '$1' (try --help)"
                ;;
        esac
    done

    [ $# -eq 0 ] || die 1 "unexpected argument '$1' (try --help)"
}

# Remove the half-written archive if the script exits early. Harmless when the
# variable is empty or the file has already been renamed into place.
cleanup() {
    if [ -n "$TMP_ARCHIVE" ] && [ -f "$TMP_ARCHIVE" ]; then
        rm -f -- "$TMP_ARCHIVE"
    fi
}

# --------------------------------------------------------------------------
# Build the list of sources. Missing files (a config that simply is not present
# on this host, e.g. /etc/network/interfaces on a systemd-networkd box) are
# skipped with a warning; unreadable files are a real problem because they
# would produce a backup with a silent hole in it.
# --------------------------------------------------------------------------
collect_sources() {
    local -a wanted=()
    local -a usable=()
    local path

    # Word-splitting is intentional here: FILES_SPEC is a whitespace-separated
    # list by contract, and we want an array rather than a single string so
    # paths with spaces inside them survive the tar invocation below.
    read -r -a wanted <<<"$FILES_SPEC"

    [ "${#wanted[@]}" -gt 0 ] || die 1 "the file list is empty"

    for path in "${wanted[@]}"; do
        if [ ! -e "$path" ]; then
            log_warn "skipping '$path': not present on this host"
            continue
        fi
        if [ ! -f "$path" ]; then
            log_warn "skipping '$path': not a regular file"
            continue
        fi
        if [ ! -r "$path" ]; then
            if [ "$ALLOW_PARTIAL" -eq 1 ]; then
                log_warn "skipping unreadable '$path' (--allow-partial)"
                continue
            fi
            die 2 "cannot read '$path' - re-run with sudo, or pass --allow-partial to skip it"
        fi
        usable+=("$path")
    done

    [ "${#usable[@]}" -gt 0 ] || die 2 "no readable files to back up"

    SOURCES=("${usable[@]}")
}

# --------------------------------------------------------------------------
# Create the destination directory with owner-only permissions. mkdir -p leaves
# an existing directory's mode alone, so the chmod is not redundant: a
# pre-existing 0755 directory would otherwise expose the archives.
# --------------------------------------------------------------------------
prepare_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log_info "[dry-run] would create $BACKUP_DIR with mode 0700"
            return 0
        fi
        mkdir -p -- "$BACKUP_DIR" || die 4 "cannot create '$BACKUP_DIR'"
        log_info "created $BACKUP_DIR"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] would enforce mode 0700 on $BACKUP_DIR"
        return 0
    fi

    chmod 0700 -- "$BACKUP_DIR" || die 4 "cannot restrict permissions on '$BACKUP_DIR'"
}

# --------------------------------------------------------------------------
# Pack and verify. The archive is written to a mktemp file inside the backup
# directory (so the final rename stays on one filesystem and is atomic) and is
# only published once gzip and the entry count both check out.
# --------------------------------------------------------------------------
create_archive() {
    local stamp final base entry_count

    stamp="$(date +%Y%m%d_%H%M%S)"
    base="${ARCHIVE_PREFIX}${stamp}.tar.gz"
    final="$BACKUP_DIR/$base"

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] would archive ${#SOURCES[@]} file(s) into $final"
        log_info "[dry-run] would verify the archive and write $final.sha256"
        return 0
    fi

    TMP_ARCHIVE="$(mktemp "$BACKUP_DIR/.${ARCHIVE_PREFIX}XXXXXX")" \
        || die 4 "cannot create a temporary file in '$BACKUP_DIR'"
    trap cleanup EXIT

    log_info "archiving ${#SOURCES[@]} file(s) into $base"
    # stderr is no longer discarded: tar's own diagnosis is the only thing that
    # explains a failure. '--' stops a path from being read as an option.
    if ! tar -czf "$TMP_ARCHIVE" -- "${SOURCES[@]}"; then
        die 4 "tar failed while creating the archive"
    fi

    if ! gzip -t "$TMP_ARCHIVE"; then
        die 3 "archive failed the gzip integrity check"
    fi

    entry_count="$(tar -tzf "$TMP_ARCHIVE" | wc -l | tr -d '[:space:]')"
    if [ "$entry_count" -ne "${#SOURCES[@]}" ]; then
        die 3 "archive holds $entry_count entries but ${#SOURCES[@]} were expected"
    fi

    # Avoid clobbering an archive from the same second (two cron runs, a manual
    # re-run): append a counter until the name is free.
    local n=1
    while [ -e "$final" ]; do
        final="$BACKUP_DIR/${ARCHIVE_PREFIX}${stamp}_${n}.tar.gz"
        n=$((n + 1))
    done

    chmod 0600 -- "$TMP_ARCHIVE"
    mv -n -- "$TMP_ARCHIVE" "$final" || die 4 "cannot move the archive into place"
    TMP_ARCHIVE=""
    trap - EXIT

    log_ok "backup created: $final"
    log_info "backup integrity (SHA256):"
    sha256sum -- "$final"
    if ! sha256sum -- "$final" >"$final.sha256"; then
        die 4 "cannot write the SHA-256 sidecar for '$final'"
    fi
    chmod 0600 -- "$final.sha256"

    CREATED_ARCHIVE="$final"
}

# --------------------------------------------------------------------------
# Retention. Archive names sort chronologically because the timestamp is fixed
# width, so a plain lexicographic sort is enough - no stat/date parsing.
# --------------------------------------------------------------------------
prune_archives() {
    local -a archives=()
    local excess i

    [ "$KEEP" -gt 0 ] || return 0

    shopt -s nullglob
    archives=("$BACKUP_DIR/${ARCHIVE_PREFIX}"*.tar.gz)
    shopt -u nullglob

    [ "${#archives[@]}" -gt "$KEEP" ] || return 0

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] would prune $(( ${#archives[@]} - KEEP )) archive(s), keeping $KEEP"
        return 0
    fi

    # Sort oldest-first. mapfile keeps paths containing spaces intact, unlike a
    # plain $(...) word-split.
    mapfile -t archives < <(printf '%s\n' "${archives[@]}" | sort)

    excess=$(( ${#archives[@]} - KEEP ))
    for ((i = 0; i < excess; i++)); do
        log_info "pruning old archive ${archives[$i]}"
        rm -f -- "${archives[$i]}" "${archives[$i]}.sha256"
    done
}

main() {
    parse_args "$@"

    SOURCES=()
    CREATED_ARCHIVE=""

    log_info "initializing critical configuration backup"
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "dry-run mode: no files will be written"
    fi

    collect_sources
    prepare_backup_dir
    create_archive
    prune_archives

    if [ "$DRY_RUN" -eq 1 ]; then
        log_ok "dry-run complete, nothing was written"
    else
        log_ok "SUCCESS: backup available at $CREATED_ARCHIVE"
    fi
}

main "$@"
