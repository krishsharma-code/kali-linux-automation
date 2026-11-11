#!/bin/bash
#
# docker_container_audit.sh
# ---------------------------------------------------------------------------
# Docker Container Security Auditor (Day 15 - Container Security)
#
# A read-only audit of the local Docker containers for the misconfigurations
# most often used in container-escape and privilege-escalation attacks:
#   * privileged mode
#   * sharing the host PID / IPC / network namespaces, or another
#     container's namespace
#   * mounting the Docker socket (grants full control of the host daemon)
#   * sensitive host path bind-mounts (/etc, /root, /, /proc, /sys, ...),
#     whether they were created with -v or with --mount
#   * dangerous added Linux capabilities (SYS_ADMIN, SYS_PTRACE, ...)
#   * unconfined seccomp / AppArmor profiles
#   * running as root with a writable root filesystem
#   * using a floating ':latest' (or missing) image tag
#
# The script never starts, stops, modifies or removes anything - it only
# reads container metadata through `docker inspect`.
#
# Requirements:
#   docker  - the CLI, with the daemon reachable by the invoking user
#   python3 - used to parse the `docker inspect` JSON document
#
# Exit codes:
#   0  the audit ran to completion (findings do NOT change the exit code)
#   1  usage error, or a pre-flight check failed (no daemon, bad -o path)
#
# Known limitations:
#   * A bind-mount path containing a newline is not reported.
#   * `docker inspect` is trusted as the source of truth; a daemon that
#     reports a container as unprivileged is believed.
#   * The report file is created with mode 0600 and truncated on every run.
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
SKIPPED=0

# ---------------------------------------------------------------------------
# Inspect parser
#
# One `docker inspect` call per container returns a single JSON document; this
# helper flattens the handful of fields the audit needs into `KEY=VALUE` lines
# so the shell never has to split on whitespace. Values are stripped of control
# characters: a container name or bind path is attacker-influenced input, and
# an embedded newline would otherwise let it forge extra report lines.
#
# Emitted keys: NAME IMAGE PRIV NET PID IPC ROFS USER
#               CAP SECOPT BIND (source) BINDDESC (full mount spec)
# ---------------------------------------------------------------------------
INSPECT_PARSER='
import json
import sys


def clean(value):
    """Return *value* with control characters removed."""
    return "".join(ch for ch in str(value) if ch.isprintable())


def emit(key, value):
    print(key + "=" + clean(value))


try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(2)

if isinstance(doc, list):
    doc = doc[0] if doc else {}
if not isinstance(doc, dict):
    sys.exit(2)

host = doc.get("HostConfig") or {}
cfg = doc.get("Config") or {}

emit("NAME", (doc.get("Name") or "").lstrip("/"))
emit("IMAGE", cfg.get("Image") or "")
emit("PRIV", "true" if host.get("Privileged") else "false")
emit("NET", host.get("NetworkMode") or "")
emit("PID", host.get("PidMode") or "")
emit("IPC", host.get("IpcMode") or "")
emit("ROFS", "true" if host.get("ReadonlyRootfs") else "false")
emit("USER", cfg.get("User") or "")

for cap in host.get("CapAdd") or []:
    emit("CAP", cap)

for opt in host.get("SecurityOpt") or []:
    emit("SECOPT", opt)

# -v / --volume binds: "source:destination[:options]". The source is the part
# before the first colon, which is all the classification below needs.
for spec in host.get("Binds") or []:
    emit("BIND", str(spec).split(":")[0])
    emit("BINDDESC", spec)

# --mount type=bind entries only appear in .Mounts, never in .Binds, so both
# sources have to be read or half the host mounts go unaudited.
for mount in doc.get("Mounts") or []:
    if not isinstance(mount, dict) or mount.get("Type") != "bind":
        continue
    source = mount.get("Source") or ""
    target = mount.get("Destination") or ""
    emit("BIND", source)
    emit("BINDDESC", source + ":" + target)
'

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
  -o, --output FILE   Also write the report to FILE (truncated, mode 0600)
  -v, --verbose       Print the full inspect summary for every container
  -h, --help          Show this help text and exit

Examples:
  ./${SCRIPT_NAME}
  ./${SCRIPT_NAME} --all --output docker_audit.txt

Exit status:
  0  audit completed (findings are reported, not returned as an error)
  1  usage error, or Docker/python3 is unavailable
EOF
}

# Print a line to stdout and, when a report file is set, append it there too.
emit() {
    printf '%s\n' "$1"
    if [[ -n "$REPORT_FILE" ]]; then
        if ! printf '%s\n' "$1" >>"$REPORT_FILE"; then
            echo "[!] Could not append to the report file; continuing on stdout only." >&2
            REPORT_FILE=""
        fi
    fi
}

# Create (or truncate) the report file, refusing paths that would either
# redirect the write somewhere else or expose the findings to other users.
prepare_report_file() {
    local path="$1"
    local dir

    dir="$(dirname -- "$path")"

    if [[ -L "$path" ]]; then
        echo "[!] Refusing to write the report through a symlink: $path" >&2
        return 1
    fi
    if [[ -d "$path" ]]; then
        echo "[!] Report path is a directory: $path" >&2
        return 1
    fi
    if [[ ! -d "$dir" ]]; then
        echo "[!] Report directory does not exist: $dir" >&2
        return 1
    fi
    if [[ ! -w "$dir" ]]; then
        echo "[!] Report directory is not writable: $dir" >&2
        return 1
    fi

    # The report lists host paths and container configuration, so it is
    # owner-only, and it is truncated so a previous run's findings cannot be
    # mistaken for this run's.
    umask 077
    if ! : >"$path"; then
        echo "[!] Could not create the report file: $path" >&2
        return 1
    fi
    chmod 600 "$path" 2>/dev/null || true
    return 0
}

# Flatten one `docker inspect` JSON document into KEY=VALUE lines.
parse_inspect() {
    python3 -c "$INSPECT_PARSER" 2>/dev/null <<<"$1"
}

# Print "tagged", "latest", "untagged" or "pinned" for an image reference.
# A registry port (registry:5000/app) is not a tag, and a digest pin
# (app@sha256:...) is reproducible even though it has no tag.
classify_image_tag() {
    local ref="$1"
    local last

    if [[ -z "$ref" ]]; then
        echo "untagged"
        return
    fi
    if [[ "$ref" == *"@"* ]]; then
        echo "pinned"
        return
    fi

    last="${ref##*/}"
    if [[ "$last" == *:* ]]; then
        if [[ "${last##*:}" == "latest" ]]; then
            echo "latest"
        else
            echo "tagged"
        fi
        return
    fi

    echo "untagged"
}

# True when the container runs as uid 0. `Config.User` is empty when it is
# unset (Docker then runs the image's user, which defaults to root) and may be
# "root", "0" or the "uid:gid" form ("0:0", "root:root").
is_root_user() {
    local user="$1"
    local uid="${user%%:*}"

    if [[ -z "$uid" || "$uid" == "root" ]]; then
        return 0
    fi
    if [[ "$uid" =~ ^0+$ ]]; then
        return 0
    fi
    return 1
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
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
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

if [[ -n "$REPORT_FILE" ]]; then
    if ! prepare_report_file "$REPORT_FILE"; then
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Pre-flight checks (fail soft, never destructive)
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    emit "[!] Docker is not installed on this host - nothing to audit."
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required to parse the 'docker inspect' output." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    emit "[!] Cannot reach the Docker daemon. Is it running, and do you have permission?"
    exit 1
fi

# Collect the container IDs to audit.
if [[ "$AUDIT_ALL" -eq 1 ]]; then
    if ! PS_OUTPUT="$(docker ps -aq 2>/dev/null)"; then
        echo "[!] 'docker ps -aq' failed; the container list could not be read." >&2
        exit 1
    fi
else
    if ! PS_OUTPUT="$(docker ps -q 2>/dev/null)"; then
        echo "[!] 'docker ps -q' failed; the container list could not be read." >&2
        exit 1
    fi
fi

mapfile -t IDS <<<"$PS_OUTPUT"

if [[ "$AUDIT_ALL" -eq 1 ]]; then
    SCOPE="all containers"
else
    SCOPE="running containers"
fi

emit "=== Docker Container Security Audit - $(date) ==="
emit "Host: $(hostname)"
emit "Scope: $SCOPE"
emit "----------------------------------------"

if [[ ${#IDS[@]} -eq 0 || -z "${IDS[0]:-}" ]]; then
    emit "[+] No containers found in scope. Nothing to audit."
    exit 0
fi

# ---------------------------------------------------------------------------
# Per-container audit
# ---------------------------------------------------------------------------
audit_container() {
    local id="$1"
    local raw parsed line key value
    local name="" image="" privileged="" netmode="" pidmode=""
    local ipcmode="" readonly_fs="" user=""
    local -a caps=() secopts=() bind_srcs=() bind_descs=()
    local -a findings=()
    local -A seen_bind=()
    local c_high=0 c_med=0 c_low=0
    local i src spec cap opt tag

    if ! raw="$(docker inspect "$id" 2>/dev/null)"; then
        emit ""
        emit "Container: ${id:0:12}"
        emit "  [!] Could not inspect this container (removed mid-audit, or permission denied). Skipped."
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if ! parsed="$(parse_inspect "$raw")" || [[ -z "$parsed" ]]; then
        emit ""
        emit "Container: ${id:0:12}"
        emit "  [!] Could not parse the inspect output for this container. Skipped."
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            NAME) name="$value" ;;
            IMAGE) image="$value" ;;
            PRIV) privileged="$value" ;;
            NET) netmode="$value" ;;
            PID) pidmode="$value" ;;
            IPC) ipcmode="$value" ;;
            ROFS) readonly_fs="$value" ;;
            USER) user="$value" ;;
            CAP) caps+=("$value") ;;
            SECOPT) secopts+=("$value") ;;
            BIND) bind_srcs+=("$value") ;;
            BINDDESC) bind_descs+=("$value") ;;
        esac
    done <<<"$parsed"

    # Privileged mode disables almost every isolation boundary.
    if [[ "$privileged" == "true" ]]; then
        findings+=("[HIGH]   Runs in privileged mode (full host device access)")
        c_high=$((c_high + 1))
    fi

    # Host namespace sharing weakens isolation between container and host.
    if [[ "$pidmode" == "host" ]]; then
        findings+=("[HIGH]   Shares the host PID namespace (PidMode=host)")
        c_high=$((c_high + 1))
    elif [[ "$pidmode" == container:* ]]; then
        findings+=("[MEDIUM] Shares another container's PID namespace (PidMode=$pidmode)")
        c_med=$((c_med + 1))
    fi
    if [[ "$netmode" == "host" ]]; then
        findings+=("[MEDIUM] Shares the host network namespace (NetworkMode=host)")
        c_med=$((c_med + 1))
    elif [[ "$netmode" == container:* ]]; then
        findings+=("[LOW]    Shares another container's network namespace (NetworkMode=$netmode)")
        c_low=$((c_low + 1))
    fi
    if [[ "$ipcmode" == "host" ]]; then
        findings+=("[MEDIUM] Shares the host IPC namespace (IpcMode=host)")
        c_med=$((c_med + 1))
    fi

    # Bind mounts: flag the Docker socket and sensitive host paths. `-v` and
    # `--mount` produce the same pair of arrays, so both are covered; a source
    # seen twice (once in each) is reported once.
    for i in "${!bind_srcs[@]}"; do
        src="${bind_srcs[$i]}"
        spec="${bind_descs[$i]:-$src}"
        [[ -n "${seen_bind[$src]:-}" ]] && continue
        seen_bind["$src"]=1
        case "$src" in
            *docker.sock|*podman.sock|*containerd.sock)
                findings+=("[HIGH]   Mounts the container runtime socket: $spec (host daemon control)")
                c_high=$((c_high + 1))
                ;;
            /|/etc|/etc/*|/root|/root/*|/home|/home/*|/var/lib/docker|/var/lib/docker/*|/proc|/proc/*|/sys|/sys/*|/boot|/boot/*)
                findings+=("[HIGH]   Mounts a sensitive host path: $spec")
                c_high=$((c_high + 1))
                ;;
            /tmp|/tmp/*|/var/tmp|/var/tmp/*)
                findings+=("[MEDIUM] Mounts a host temp path: $spec")
                c_med=$((c_med + 1))
                ;;
        esac
    done

    # Extra Linux capabilities effectively re-grant root-level powers.
    if [[ ${#caps[@]} -gt 0 ]]; then
        for cap in "${caps[@]}"; do
            case "$cap" in
                SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)
                    findings+=("[HIGH]   Dangerous capability added: CAP_$cap")
                    c_high=$((c_high + 1))
                    ;;
                NET_ADMIN|NET_RAW)
                    findings+=("[MEDIUM] Elevated capability added: CAP_$cap")
                    c_med=$((c_med + 1))
                    ;;
            esac
        done
    fi

    # An unconfined seccomp/AppArmor profile removes the syscall filter that
    # makes most kernel exploits harder to reach.
    if [[ ${#secopts[@]} -gt 0 ]]; then
        for opt in "${secopts[@]}"; do
            case "$opt" in
                *seccomp=unconfined*|*apparmor=unconfined*|*label=disable*)
                    findings+=("[MEDIUM] Unconfined security profile: $opt")
                    c_med=$((c_med + 1))
                    ;;
            esac
        done
    fi

    # Running as root: riskier when the root filesystem is writable.
    if is_root_user "$user"; then
        if [[ "$readonly_fs" == "true" ]]; then
            findings+=("[LOW]    Runs as root but the root filesystem is read-only")
            c_low=$((c_low + 1))
        else
            findings+=("[MEDIUM] Runs as root with a writable root filesystem")
            c_med=$((c_med + 1))
        fi
    fi

    # Floating tags make builds non-reproducible.
    tag="$(classify_image_tag "$image")"
    case "$tag" in
        latest)
            findings+=("[LOW]    Uses the floating ':latest' tag: ${image:-<none>}")
            c_low=$((c_low + 1))
            ;;
        untagged)
            findings+=("[LOW]    Image reference has no tag (implicitly ':latest'): ${image:-<none>}")
            c_low=$((c_low + 1))
            ;;
    esac

    # --- Report this container ---
    emit ""
    emit "Container: ${name:-<unknown>} (${id:0:12})"
    emit "Image:     ${image:-<none>}"

    if [[ ${#findings[@]} -eq 0 ]]; then
        emit "  [+] No issues detected."
    else
        local f
        for f in "${findings[@]}"; do
            emit "  $f"
        done
    fi

    HIGH=$((HIGH + c_high))
    MEDIUM=$((MEDIUM + c_med))
    LOW=$((LOW + c_low))

    if [[ "$VERBOSE" -eq 1 ]]; then
        emit "  [i] Raw config: privileged=$privileged pid=$pidmode net=$netmode ipc=$ipcmode user=${user:-<default>}"
        emit "  [i] caps=${caps[*]:-<none>} security-opt=${secopts[*]:-<none>} binds=${#bind_srcs[@]}"
    fi
}

for id in "${IDS[@]}"; do
    [[ -z "$id" ]] && continue

    # Container IDs come from the daemon; validate before using them as an
    # argument so unexpected output cannot be reinterpreted as a CLI flag.
    if [[ ! "$id" =~ ^[0-9a-fA-F]{12,64}$ ]]; then
        emit ""
        emit "Container: ${id:0:20}"
        emit "  [!] Ignoring an unexpected container identifier from 'docker ps'."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    CONTAINERS=$((CONTAINERS + 1))
    audit_container "$id"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
emit ""
emit "----------------------------------------"
emit "Audited $CONTAINERS container(s)."
if [[ "$SKIPPED" -gt 0 ]]; then
    emit "Skipped $SKIPPED container(s) that could not be read."
fi
emit "Findings -> HIGH: $HIGH | MEDIUM: $MEDIUM | LOW: $LOW"
if [[ -n "$REPORT_FILE" ]]; then
    emit "[+] Report written to: $REPORT_FILE"
fi
emit "[+] Audit complete. No changes were made to the host or containers."
