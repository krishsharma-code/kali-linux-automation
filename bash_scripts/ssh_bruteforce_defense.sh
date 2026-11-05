#!/usr/bin/env bash
# SAFE_HELP_GUARD: non-destructive --help (exits before any state change).
#
# ssh_bruteforce_defense.sh - rank source IPs by failed SSH logins and
# optionally deny the worst offenders at the firewall.
#
# Day 5-7: Defensive Monitoring & Log Analysis
#
# Pipeline:
#   1. Read an auth log (--log, else /var/log/auth.log, else /var/log/syslog).
#   2. Keep only "Failed password" lines and pull the IPv4 address out of each
#      one with a regex. The address is never taken by token position, so an
#      extra word in the log line (for example "invalid user admin") cannot
#      shift the field and put a username or a free-text token into the
#      firewall ruleset.
#   3. Validate every candidate as a real IPv4 address (four octets, 0-255)
#      before it is counted, reported or handed to ufw.
#   4. Report every IP at or above the threshold. With --apply, deny each one
#      with ufw, skipping addresses that are already denied.
#
# The default run is a read-only report. Nothing changes the firewall unless
# --apply is passed, and --apply refuses to run without root.
#
# Usage:
#   ./ssh_bruteforce_defense.sh [--log FILE] [--threshold N]
#                               [--state-file FILE] [--apply | --dry-run]
#
# Exit codes:
#   0  report completed (offenders found or not)
#   1  usage error, unreadable log, or a failed ufw call
#   3  --apply requested without root, or ufw is not installed

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
DEFAULT_THRESHOLD=5
# Candidate addresses are matched, then re-validated in bash before use.
IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

LOG_FILE=""
THRESHOLD="$DEFAULT_THRESHOLD"
STATE_FILE=""
APPLY=0

WORK_DIR=""

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [options]

Ranks source IPs by the number of failed SSH password attempts in an auth log
and reports those at or above a threshold.

Options:
  --log FILE         Auth log to read. Default: /var/log/auth.log, then
                     /var/log/syslog.
  --threshold N      Failed attempts before an IP is reported. Default: $DEFAULT_THRESHOLD.
  --state-file FILE  Also write the ranked "count ip" list to FILE (mode 600).
  --apply            Deny the offending IPs with ufw. Requires root.
                     Without this flag the script only reports.
  --dry-run          Explicitly report only (the default behaviour).
  -h, --help         Show this help and exit. Makes no changes.

Examples:
  sudo $SCRIPT_NAME                       # report only
  sudo $SCRIPT_NAME --apply               # report and deny offenders
  $SCRIPT_NAME --log /tmp/auth.log --threshold 3 --state-file /tmp/blocked.txt

This tool changes firewall state only with --apply. --help makes no changes.
EOF
}

die() {
    printf '[!] Fatal: %s\n' "$*" >&2
    exit 1
}

usage_error() {
    printf '[!] Error: %s\n' "$*" >&2
    printf "Try '%s --help' for usage.\n" "$SCRIPT_NAME" >&2
    exit 1
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
}

trap cleanup EXIT INT TERM

# is_valid_ipv4 ADDR - true when ADDR is dotted-quad IPv4 with each octet 0-255.
is_valid_ipv4() {
    local addr="$1" octet
    [[ "$addr" =~ $IPV4_RE ]] || return 1
    local -a octets
    IFS='.' read -r -a octets <<< "$addr"
    for octet in "${octets[@]}"; do
        # 10# forces base-10 so "010" is ten and not an octal error.
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}

# parse_args - populate the globals above, or exit on a bad invocation.
parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --log)
                (( $# >= 2 )) || usage_error "--log needs a file argument"
                LOG_FILE="$2"
                shift 2
                ;;
            --threshold)
                (( $# >= 2 )) || usage_error "--threshold needs a number"
                THRESHOLD="$2"
                shift 2
                ;;
            --state-file)
                (( $# >= 2 )) || usage_error "--state-file needs a path"
                STATE_FILE="$2"
                shift 2
                ;;
            --apply)
                APPLY=1
                shift
                ;;
            --dry-run)
                APPLY=0
                shift
                ;;
            *)
                usage_error "unknown option: $1"
                ;;
        esac
    done

    # The threshold lands in an arithmetic comparison, so it must be a plain
    # non-negative integer before it is used.
    if [[ ! "$THRESHOLD" =~ ^[0-9]+$ ]]; then
        usage_error "--threshold must be a non-negative integer, got: $THRESHOLD"
    fi
}

# resolve_log_file - pick and verify a readable log, or exit.
resolve_log_file() {
    if [[ -n "$LOG_FILE" ]]; then
        [[ -e "$LOG_FILE" ]] || die "log file not found: $LOG_FILE"
    elif [[ -e /var/log/auth.log ]]; then
        LOG_FILE=/var/log/auth.log
    elif [[ -e /var/log/syslog ]]; then
        LOG_FILE=/var/log/syslog
    else
        die "no auth log found (tried --log, /var/log/auth.log, /var/log/syslog)"
    fi

    [[ -r "$LOG_FILE" ]] || die "log file is not readable: $LOG_FILE (try sudo)"
}

# collect_counts - print "count ip" lines, highest count first, to stdout.
# Only syntactically valid IPv4 addresses survive; anything else is dropped
# here rather than downstream.
collect_counts() {
    local raw
    raw="$(grep -E 'Failed password' -- "$LOG_FILE" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true)"

    [[ -n "$raw" ]] || return 0

    local ip
    while IFS= read -r ip; do
        is_valid_ipv4 "$ip" && printf '%s\n' "$ip"
    done <<< "$raw" | sort | uniq -c | sort -k1,1nr -k2,2
}

# write_state_file FILE CONTENT - write atomically, owner-only, no symlink follow.
write_state_file() {
    local target="$1" content="$2" dir tmp
    dir="$(dirname -- "$target")"
    [[ -d "$dir" ]] || die "state file directory does not exist: $dir"

    tmp="$(mktemp "$dir/.ssh_bf_state.XXXXXX")" || die "cannot create a temp file in $dir"
    printf '%s\n' "$content" > "$tmp"
    chmod 600 -- "$tmp"
    mv -f -- "$tmp" "$target" || die "cannot write state file: $target"
}

# denied_ips - print the addresses ufw already lists as blocked, one per line.
denied_ips() {
    ufw status 2>/dev/null | awk 'NF >= 3 { print $1 }'
}

# deny_ip ADDR - deny ADDR at the top of the ufw chain; true on success.
deny_ip() {
    local addr="$1"
    ufw insert 1 deny from "$addr" to any >/dev/null 2>&1
}

main() {
    parse_args "$@"
    resolve_log_file

    if (( APPLY == 1 )); then
        if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
            printf '[!] Fatal: --apply changes firewall rules and must run as root.\n' >&2
            exit 3
        fi
        command -v ufw >/dev/null 2>&1 || {
            printf '[!] Fatal: --apply needs ufw, which is not installed.\n' >&2
            exit 3
        }
    fi

    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh_bf.XXXXXX")" || die "cannot create a temp directory"
    chmod 700 -- "$WORK_DIR"

    echo "=== SSH Brute Force Defense System ==="
    echo "[*] Reading $LOG_FILE (threshold: $THRESHOLD failed attempts)"

    local counts
    counts="$(collect_counts)"

    if [[ -z "$counts" ]]; then
        echo "[+] No failed password attempts found in $LOG_FILE."
        [[ -n "$STATE_FILE" ]] && write_state_file "$STATE_FILE" ""
        echo "[+] Nothing to report."
        return 0
    fi

    if [[ -n "$STATE_FILE" ]]; then
        write_state_file "$STATE_FILE" "$counts"
        echo "[*] Ranked list written to $STATE_FILE"
    fi

    # Cache the firewall view once: ufw status is slow and calling it per IP
    # inside the loop is what made the original script crawl on large logs.
    local denied=""
    if (( APPLY == 1 )); then
        denied="$(denied_ips)"
    fi

    local offenders=0 already=0 blocked=0 failed=0 count ip
    while read -r count ip; do
        [[ -n "${ip:-}" ]] || continue
        (( count >= THRESHOLD )) || continue
        offenders=$(( offenders + 1 ))
        echo "[!] HIGH ALERT: IP $ip has $count failed attempts."

        if (( APPLY == 0 )); then
            echo "    [*] Report only. Re-run with --apply to deny this address."
            continue
        fi

        # Exact line match: 203.0.113.7 must not be considered blocked just
        # because 203.0.113.70 appears in the ruleset.
        if [[ -n "$denied" ]] && grep -qxF -- "$ip" <<< "$denied"; then
            echo "    [*] IP $ip is already denied."
            already=$(( already + 1 ))
            continue
        fi

        # Print before acting, so the change is visible in the transcript.
        echo "    [+] Denying $ip with ufw..."
        if deny_ip "$ip"; then
            blocked=$(( blocked + 1 ))
        else
            echo "    [!] ufw refused to deny $ip; continuing." >&2
            failed=$(( failed + 1 ))
        fi
    done <<< "$counts"

    echo "---"
    echo "[+] Scan complete. $offenders IP(s) at or above $THRESHOLD attempts."
    if (( APPLY == 1 )); then
        echo "[+] Newly denied: $blocked  Already denied: $already  Failed: $failed"
        (( failed == 0 )) || return 1
    fi
    return 0
}

main "$@"
