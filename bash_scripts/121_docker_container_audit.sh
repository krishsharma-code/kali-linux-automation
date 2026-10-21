#!/bin/bash
#
# 121_docker_container_audit.sh
# ---------------------------------------------------------------------------
# Docker Container Security Auditor (Day 15 - Container Security)
#
# A read-only audit of the local Docker containers for the misconfigurations
# most often used in container-escape and privilege-escalation attacks:
#   * privileged mode
#   * sharing the host PID / IPC / network namespaces
#   * mounting the Docker socket (grants full control of the host daemon)
#   * sensitive host path bind-mounts (/etc, /root, /, /home, ...)
#   * dangerous added Linux capabilities (SYS_ADMIN, SYS_PTRACE, ...)
#   * running as root with a writable root filesystem
#   * using a floating ':latest' image tag
#
# The script never starts, stops, modifies or removes anything - it only
# reads container metadata through `docker inspect`.
# ---------------------------------------------------------------------------

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
REPORT_FILE=""
VERBOSE=0
AUDIT_ALL=0

HIGH=0
MEDIUM=0
LOW=0
CONTAINERS=0

# ---------------------------------------------------------------------------
# Help / usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Docker Container Security Auditor

Usage: ./${SCRIPT_NAME} [OPTIONS]

Read-only audit of running Docker containers for privilege and escape
risks. Nothing is modified on the host or in the containers.

Options:
  -a, --all           Audit all containers (default: only running ones)
  -o, --output FILE   Also write the report to FILE
  -v, --verbose       Print the full inspect summary for every container
  -h, --help          Show this help text and exit

Examples:
  ./${SCRIPT_NAME}
  ./${SCRIPT_NAME} --all --output docker_audit.txt
EOF
}

# Print a line to stdout and, when a report file is set, append it there too.
emit() {
    printf '%s\n' "$1"
    if [[ -n "$REPORT_FILE" ]]; then
        printf '%s\n' "$1" >>"$REPORT_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -a|--all)
            AUDIT_ALL=1
            shift
            ;;
        -o|--output)
            if [[ -z "${2:-}" ]]; then
                echo "[!] Option $1 requires a file argument" >&2
                exit 1
            fi
            REPORT_FILE="$2"
            shift 2
            ;;
        *)
            echo "[!] Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks (fail soft, never destructive)
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    emit "[!] Docker is not installed on this host - nothing to audit."
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    emit "[!] Cannot reach the Docker daemon. Is it running, and do you have permission?"
    exit 1
fi

# Collect the container IDs to audit.
if [[ "$AUDIT_ALL" -eq 1 ]]; then
    mapfile -t IDS < <(docker ps -aq)
else
    mapfile -t IDS < <(docker ps -q)
fi

emit "=== Docker Container Security Audit - $(date) ==="
emit "Host: $(hostname)"
emit "Scope: $([[ "$AUDIT_ALL" -eq 1 ]] && echo "all containers" || echo "running containers")"
emit "----------------------------------------"

if [[ ${#IDS[@]} -eq 0 || -z "${IDS[0]:-}" ]]; then
    emit "[+] No containers found in scope. Nothing to audit."
    exit 0
fi

# ---------------------------------------------------------------------------
# Per-container audit
# ---------------------------------------------------------------------------
for id in "${IDS[@]}"; do
    [[ -z "$id" ]] && continue
    CONTAINERS=$((CONTAINERS + 1))

    name="$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')"
    image="$(docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null)"
    privileged="$(docker inspect -f '{{.HostConfig.Privileged}}' "$id" 2>/dev/null)"
    netmode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null)"
    pidmode="$(docker inspect -f '{{.HostConfig.PidMode}}' "$id" 2>/dev/null)"
    ipcmode="$(docker inspect -f '{{.HostConfig.IpcMode}}' "$id" 2>/dev/null)"
    readonly_fs="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id" 2>/dev/null)"
    user="$(docker inspect -f '{{.Config.User}}' "$id" 2>/dev/null)"
    caps="$(docker inspect -f '{{range .HostConfig.CapAdd}}{{.}} {{end}}' "$id" 2>/dev/null)"
    binds="$(docker inspect -f '{{range .HostConfig.Binds}}{{.}} {{end}}' "$id" 2>/dev/null)"

    declare -a FINDINGS=()
    c_high=0
    c_med=0
    c_low=0

    # Privileged mode disables almost every isolation boundary.
    if [[ "$privileged" == "true" ]]; then
        FINDINGS+=("[HIGH]   Runs in privileged mode (full host device access)")
        c_high=$((c_high + 1))
    fi

    # Host namespace sharing weakens isolation between container and host.
    if [[ "$pidmode" == "host" ]]; then
        FINDINGS+=("[HIGH]   Shares the host PID namespace (PidMode=host)")
        c_high=$((c_high + 1))
    fi
    if [[ "$netmode" == "host" ]]; then
        FINDINGS+=("[MEDIUM] Shares the host network namespace (NetworkMode=host)")
        c_med=$((c_med + 1))
    fi
    if [[ "$ipcmode" == "host" ]]; then
        FINDINGS+=("[MEDIUM] Shares the host IPC namespace (IpcMode=host)")
        c_med=$((c_med + 1))
    fi

    # Bind mounts: flag the Docker socket and sensitive host paths.
    for b in $binds; do
        src="${b%%:*}"
        case "$src" in
            *docker.sock)
                FINDINGS+=("[HIGH]   Mounts the Docker socket: $b (host daemon control)")
                c_high=$((c_high + 1))
                ;;
            /|/etc|/etc/*|/root|/root/*|/home|/var/lib/docker)
                FINDINGS+=("[HIGH]   Mounts a sensitive host path: $b")
                c_high=$((c_high + 1))
                ;;
            /tmp|/tmp/*|/var/tmp)
                FINDINGS+=("[MEDIUM] Mounts a host temp path: $b")
                c_med=$((c_med + 1))
                ;;
        esac
    done

    # Extra Linux capabilities effectively re-grant root-level powers.
    for cap in $caps; do
        case "$cap" in
            SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)
                FINDINGS+=("[HIGH]   Dangerous capability added: CAP_$cap")
                c_high=$((c_high + 1))
                ;;
            NET_ADMIN|NET_RAW)
                FINDINGS+=("[MEDIUM] Elevated capability added: CAP_$cap")
                c_med=$((c_med + 1))
                ;;
        esac
    done

    # Running as root: riskier when the root filesystem is writable.
    if [[ -z "$user" || "$user" == "0" || "$user" == "root" ]]; then
        if [[ "$readonly_fs" == "true" ]]; then
            FINDINGS+=("[LOW]    Runs as root but the root filesystem is read-only")
            c_low=$((c_low + 1))
        else
            FINDINGS+=("[MEDIUM] Runs as root with a writable root filesystem")
            c_med=$((c_med + 1))
        fi
    fi

    # Floating ':latest' tag makes builds non-reproducible.
    if [[ "$image" == *:latest || "$image" != *:* ]]; then
        FINDINGS+=("[LOW]    Uses a floating image tag: ${image:-<none>}")
        c_low=$((c_low + 1))
    fi

    # --- Report this container ---
    emit ""
    emit "Container: ${name:-<unknown>} (${id:0:12})"
    emit "Image:     ${image:-<none>}"

    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        emit "  [+] No issues detected."
    else
        for f in "${FINDINGS[@]}"; do
            emit "  $f"
        done
    fi

    HIGH=$((HIGH + c_high))
    MEDIUM=$((MEDIUM + c_med))
    LOW=$((LOW + c_low))

    if [[ "$VERBOSE" -eq 1 ]]; then
        emit "  [i] Raw config: privileged=$privileged pid=$pidmode net=$netmode ipc=$ipcmode user=${user:-<default>}"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
emit ""
emit "----------------------------------------"
emit "Audited $CONTAINERS container(s)."
emit "Findings -> HIGH: $HIGH | MEDIUM: $MEDIUM | LOW: $LOW"
if [[ -n "$REPORT_FILE" ]]; then
    emit "[+] Report written to: $REPORT_FILE"
fi
emit "[+] Audit complete. No changes were made to the host or containers."
