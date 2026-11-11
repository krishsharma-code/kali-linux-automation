"""End-to-end tests for ``bash_scripts/docker_container_audit.sh``.

The script talks to Docker only through the ``docker`` CLI, so the tests put a
stub ``docker`` executable at the front of ``PATH``. The stub serves canned
``docker inspect`` documents, which lets the audit logic (mount classification,
user parsing, image-tag classification, failure handling and report-file
hardening) be exercised without a Docker daemon.
"""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "bash_scripts" / "docker_container_audit.sh"
BASH = shutil.which("bash") or "/bin/bash"


def container_id(index):
    """Deterministic 64-character id for the container at *index*."""
    return f"{index + 1:012x}" + "0" * 52

DOCKER_STUB = """#!/bin/bash
set -uo pipefail
cmd="${1:-}"
case "$cmd" in
    info)
        [[ "${STUB_INFO_FAIL:-0}" == "1" ]] && exit 1
        exit 0
        ;;
    ps)
        [[ "${STUB_PS_FAIL:-0}" == "1" ]] && exit 1
        cat "$STUB_DIR/ps_ids" 2>/dev/null || true
        exit 0
        ;;
    inspect)
        id="${2:-}"
        [[ "${STUB_INSPECT_FAIL:-0}" == "1" ]] && exit 1
        [[ -f "$STUB_DIR/inspect_$id.json" ]] || exit 1
        cat "$STUB_DIR/inspect_$id.json"
        exit 0
        ;;
esac
exit 1
"""


def make_container(
    name="web",
    image="nginx:1.25",
    privileged=False,
    network_mode="bridge",
    pid_mode="",
    ipc_mode="private",
    readonly_rootfs=False,
    user="",
    binds=None,
    mounts=None,
    cap_add=None,
    security_opt=None,
):
    """Build a document shaped like one element of ``docker inspect`` output."""
    return {
        "Name": "/" + name,
        "Config": {"Image": image, "User": user},
        "HostConfig": {
            "Privileged": privileged,
            "NetworkMode": network_mode,
            "PidMode": pid_mode,
            "IpcMode": ipc_mode,
            "ReadonlyRootfs": readonly_rootfs,
            "Binds": binds or [],
            "CapAdd": cap_add or [],
            "SecurityOpt": security_opt or [],
        },
        "Mounts": mounts or [],
    }


class AuditRun:
    """Result of one script invocation."""

    def __init__(self, completed):
        self.returncode = completed.returncode
        self.stdout = completed.stdout
        self.stderr = completed.stderr

    def __str__(self):
        return (
            f"exit={self.returncode}\n--- stdout ---\n{self.stdout}"
            f"\n--- stderr ---\n{self.stderr}"
        )


@pytest.fixture()
def audit(tmp_path):
    """Return a runner that audits the supplied containers."""

    def _run(containers, args=(), env_overrides=None, ps_ids=None):
        stub_dir = tmp_path / "stub"
        stub_dir.mkdir(exist_ok=True)

        docker = stub_dir / "docker"
        docker.write_text(DOCKER_STUB, encoding="utf-8")
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        ids = []
        for index, container in enumerate(containers):
            cid = container_id(index)
            ids.append(cid)
            (stub_dir / f"inspect_{cid}.json").write_text(
                json.dumps(container), encoding="utf-8"
            )

        (stub_dir / "ps_ids").write_text(
            "\n".join(ps_ids if ps_ids is not None else ids) + ("\n" if ids else ""),
            encoding="utf-8",
        )

        env = dict(os.environ)
        env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
        env["STUB_DIR"] = str(stub_dir)
        env.update(env_overrides or {})

        completed = subprocess.run(
            [BASH, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(tmp_path),
        )
        return AuditRun(completed)

    return _run


def test_help_exits_zero(audit):
    result = audit([], args=["--help"])
    assert result.returncode == 0, result
    assert "Read-only audit of running Docker containers" in result.stdout
    assert "--output" in result.stdout


def test_unknown_option_is_rejected(audit):
    result = audit([], args=["--nope"])
    assert result.returncode == 1, result
    assert "Unknown option" in result.stderr


def test_output_option_requires_a_value(audit):
    result = audit([], args=["-o"])
    assert result.returncode == 1, result
    assert "requires a file argument" in result.stderr


def test_missing_docker_is_not_an_error(tmp_path):
    env = dict(os.environ)
    env["PATH"] = str(tmp_path / "empty-bin")
    completed = subprocess.run(
        [BASH, str(SCRIPT)], capture_output=True, text=True, env=env
    )
    assert completed.returncode == 0
    assert "Docker is not installed" in completed.stdout


def test_unreachable_daemon_exits_one(audit):
    result = audit([], env_overrides={"STUB_INFO_FAIL": "1"})
    assert result.returncode == 1, result
    assert "Cannot reach the Docker daemon" in result.stdout


def test_ps_failure_is_reported_not_treated_as_empty(audit):
    result = audit([], env_overrides={"STUB_PS_FAIL": "1"})
    assert result.returncode == 1, result
    assert "could not be read" in result.stderr
    assert "No containers found" not in result.stdout


def test_no_containers(audit):
    result = audit([])
    assert result.returncode == 0, result
    assert "No containers found in scope" in result.stdout


def test_privileged_and_host_pid_are_high(audit):
    result = audit([make_container(privileged=True, pid_mode="host")])
    assert result.returncode == 0, result
    assert "Runs in privileged mode" in result.stdout
    assert "Shares the host PID namespace" in result.stdout
    assert "HIGH: 2" in result.stdout


def test_clean_container_reports_no_issues(audit):
    result = audit(
        [
            make_container(
                image="nginx:1.25",
                user="1000:1000",
                readonly_rootfs=True,
            )
        ]
    )
    assert result.returncode == 0, result
    assert "No issues detected" in result.stdout
    assert "HIGH: 0 | MEDIUM: 0 | LOW: 0" in result.stdout


def test_docker_socket_bind_is_high(audit):
    result = audit(
        [make_container(binds=["/var/run/docker.sock:/var/run/docker.sock"])]
    )
    assert "Mounts the container runtime socket" in result.stdout
    assert "HIGH: 1" in result.stdout


def test_mount_flag_bind_is_audited_even_when_binds_is_empty(audit):
    """``--mount type=bind`` never appears in HostConfig.Binds."""
    result = audit(
        [
            make_container(
                binds=[],
                mounts=[
                    {
                        "Type": "bind",
                        "Source": "/etc",
                        "Destination": "/host-etc",
                    }
                ],
            )
        ]
    )
    assert "Mounts a sensitive host path: /etc:/host-etc" in result.stdout


def test_volume_mounts_are_not_reported_as_binds(audit):
    result = audit(
        [
            make_container(
                mounts=[
                    {"Type": "volume", "Source": "/etc", "Destination": "/data"}
                ]
            )
        ]
    )
    assert "sensitive host path" not in result.stdout


def test_bind_source_with_spaces_is_one_finding(audit):
    result = audit([make_container(binds=["/home/my user:/data"])])
    assert "Mounts a sensitive host path: /home/my user:/data" in result.stdout
    assert "HIGH: 1" in result.stdout


def test_duplicate_bind_reported_once(audit):
    result = audit(
        [
            make_container(
                binds=["/etc:/etc"],
                mounts=[{"Type": "bind", "Source": "/etc", "Destination": "/etc"}],
            )
        ]
    )
    assert result.stdout.count("Mounts a sensitive host path") == 1


@pytest.mark.parametrize("user", ["", "0", "root", "0:0", "root:root", "000"])
def test_root_forms_are_detected(audit, user):
    result = audit([make_container(user=user)])
    assert "Runs as root with a writable root filesystem" in result.stdout


@pytest.mark.parametrize("user", ["1000", "1000:1000", "appuser"])
def test_non_root_user_is_not_flagged(audit, user):
    result = audit([make_container(user=user)])
    assert "Runs as root" not in result.stdout


def test_readonly_rootfs_downgrades_root_finding(audit):
    result = audit([make_container(user="0", readonly_rootfs=True)])
    assert "Runs as root but the root filesystem is read-only" in result.stdout


def test_latest_tag_is_flagged(audit):
    result = audit([make_container(image="nginx:latest")])
    assert "floating ':latest' tag" in result.stdout


def test_missing_tag_is_flagged(audit):
    result = audit([make_container(image="nginx")])
    assert "has no tag" in result.stdout


def test_registry_port_is_not_mistaken_for_a_tag(audit):
    result = audit([make_container(image="registry.local:5000/app")])
    assert "has no tag" in result.stdout


def test_pinned_and_tagged_images_are_not_flagged(audit):
    for image in ("nginx:1.25", "registry.local:5000/app:1.2.3"):
        result = audit([make_container(image=image)])
        assert "floating" not in result.stdout, image
        assert "has no tag" not in result.stdout, image


def test_digest_pinned_image_is_not_flagged(audit):
    result = audit([make_container(image="nginx@sha256:" + "a" * 64)])
    assert "floating" not in result.stdout
    assert "has no tag" not in result.stdout


def test_dangerous_capability_is_high(audit):
    result = audit([make_container(cap_add=["SYS_ADMIN", "NET_RAW"])])
    assert "Dangerous capability added: CAP_SYS_ADMIN" in result.stdout
    assert "Elevated capability added: CAP_NET_RAW" in result.stdout


def test_unconfined_security_profile_is_medium(audit):
    result = audit([make_container(security_opt=["seccomp=unconfined"])])
    assert "Unconfined security profile: seccomp=unconfined" in result.stdout


def test_uninspectable_container_is_skipped_not_flagged(audit):
    """A container removed mid-audit must not become a false root finding."""
    result = audit(
        [make_container(user="1000:1000")],
        ps_ids=[container_id(0), "2" * 12 + "0" * 52],
    )
    assert result.returncode == 0, result
    assert "Could not inspect this container" in result.stdout
    assert "Skipped 1 container(s)" in result.stdout
    assert "Runs as root" not in result.stdout


def test_malformed_inspect_json_is_skipped(audit, tmp_path):
    result = audit([make_container()])
    stub_dir = tmp_path / "stub"
    broken = next(stub_dir.glob("inspect_*.json"))
    broken.write_text("{not json", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
    env["STUB_DIR"] = str(stub_dir)
    completed = subprocess.run(
        [BASH, str(SCRIPT)], capture_output=True, text=True, env=env, cwd=str(tmp_path)
    )

    assert completed.returncode == 0
    assert "Could not parse the inspect output" in completed.stdout


def test_unexpected_container_id_is_ignored(audit):
    result = audit([], ps_ids=["--privileged"])
    assert result.returncode == 0, result
    assert "Ignoring an unexpected container identifier" in result.stdout
    assert "Audited 0 container(s)" in result.stdout


def test_report_file_is_written_truncated_and_owner_only(audit, tmp_path):
    report = tmp_path / "audit.txt"
    report.write_text("stale output from an earlier run\n", encoding="utf-8")

    result = audit([make_container(privileged=True)], args=["-o", str(report)])
    assert result.returncode == 0, result

    content = report.read_text(encoding="utf-8")
    assert "stale output" not in content
    assert "Runs in privileged mode" in content
    assert "Audit complete" in content
    assert stat.S_IMODE(report.stat().st_mode) == 0o600


def test_report_file_refuses_symlink(audit, tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("do not touch\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    result = audit([make_container()], args=["-o", str(link)])
    assert result.returncode == 1, result
    assert "symlink" in result.stderr
    assert target.read_text(encoding="utf-8") == "do not touch\n"


def test_report_file_rejects_missing_directory(audit, tmp_path):
    result = audit(
        [make_container()], args=["-o", str(tmp_path / "nope" / "audit.txt")]
    )
    assert result.returncode == 1, result
    assert "Report directory does not exist" in result.stderr


def test_all_flag_uses_the_all_containers_scope(audit):
    result = audit([make_container()], args=["--all"])
    assert "Scope: all containers" in result.stdout


def test_control_characters_cannot_forge_report_lines(audit):
    result = audit([make_container(name="web\n  [HIGH]   forged finding")])
    forged = [
        line
        for line in result.stdout.splitlines()
        if line.strip().startswith("[HIGH]   forged")
    ]
    assert forged == [], result
