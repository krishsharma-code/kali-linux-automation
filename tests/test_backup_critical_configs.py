"""Tests for bash_scripts/backup_critical_configs.sh.

The script is exercised through its real command-line interface with a
throwaway backup directory and a throwaway source list, so the tests never
touch /etc and never need root. The properties that matter are the security
ones: the archive and its directory must be owner-only, the archive must be
verified before it is published, and unreadable sources must fail loudly
instead of producing a backup with a silent hole in it.
"""

import hashlib
import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "bash_scripts" / "backup_critical_configs.sh"


def run_script(*args, env=None):
    """Run the script with a clean environment and return the completed process."""
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if env:
        base_env.update(env)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=base_env,
        check=False,
    )


@pytest.fixture()
def sources(tmp_path):
    """Two small files standing in for the critical config files."""
    src = tmp_path / "sources"
    src.mkdir()
    first = src / "passwd"
    first.write_text("root:x:0:0:root:/root:/bin/bash\n")
    second = src / "sshd_config"
    second.write_text("PermitRootLogin no\n")
    return src


@pytest.fixture()
def backup_dir(tmp_path):
    return tmp_path / "backups"


def archive_list(backup_dir):
    return sorted(backup_dir.glob("critical_configs_*.tar.gz"))


def test_script_exists_and_is_syntactically_valid():
    assert SCRIPT.is_file()
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_help_exits_zero_without_touching_the_filesystem(tmp_path):
    result = run_script("--help")
    assert result.returncode == 0
    assert "backup_critical_configs.sh" in result.stdout
    assert "--dry-run" in result.stdout
    assert list(tmp_path.iterdir()) == []


def test_unknown_option_is_a_usage_error():
    result = run_script("--nope")
    assert result.returncode == 1
    assert "unknown option" in result.stderr


def test_keep_rejects_non_numeric_value(backup_dir, sources):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
        "--keep", "many",
    )
    assert result.returncode == 1
    assert "non-negative integer" in result.stderr
    assert not backup_dir.exists()


def test_creates_verified_archive_with_sidecar(backup_dir, sources):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd {sources}/sshd_config",
    )
    assert result.returncode == 0, result.stderr

    archives = archive_list(backup_dir)
    assert len(archives) == 1
    archive = archives[0]

    # Both sources made it into the archive.
    listing = subprocess.run(
        ["tar", "-tzf", str(archive)], capture_output=True, text=True, check=True
    ).stdout.split()
    assert any(entry.endswith("passwd") for entry in listing)
    assert any(entry.endswith("sshd_config") for entry in listing)

    # The sidecar matches the archive byte for byte.
    sidecar = Path(str(archive) + ".sha256")
    assert sidecar.is_file()
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert expected in sidecar.read_text()


def test_archive_and_directory_are_owner_only(backup_dir, sources):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
    )
    assert result.returncode == 0, result.stderr

    archive = archive_list(backup_dir)[0]
    sidecar = Path(str(archive) + ".sha256")
    dir_mode = stat.S_IMODE(backup_dir.stat().st_mode)
    archive_mode = stat.S_IMODE(archive.stat().st_mode)
    sidecar_mode = stat.S_IMODE(sidecar.stat().st_mode)

    assert dir_mode == 0o700, f"backup dir mode is {oct(dir_mode)}"
    assert archive_mode == 0o600, f"archive mode is {oct(archive_mode)}"
    assert sidecar_mode == 0o600, f"sidecar mode is {oct(sidecar_mode)}"


def test_existing_world_readable_directory_is_tightened(backup_dir, sources):
    backup_dir.mkdir()
    backup_dir.chmod(0o755)

    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(backup_dir.stat().st_mode) == 0o700


def test_missing_source_is_skipped_with_a_warning(backup_dir, sources):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd {sources}/does_not_exist",
    )
    assert result.returncode == 0, result.stderr
    assert "not present on this host" in result.stderr
    assert len(archive_list(backup_dir)) == 1


def test_no_readable_sources_fails(backup_dir, tmp_path):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", str(tmp_path / "missing_one") + " " + str(tmp_path / "missing_two"),
    )
    assert result.returncode == 2
    assert "no readable files" in result.stderr
    assert archive_list(backup_dir) == []


def test_unreadable_source_fails_unless_partial_is_allowed(backup_dir, sources):
    secret = sources / "shadow"
    secret.write_text("root:$6$hash\n")
    secret.chmod(0o000)

    if os.geteuid() == 0:
        pytest.skip("root can read a 0000 file, so the unreadable path cannot be simulated")

    try:
        result = run_script(
            "--backup-dir", str(backup_dir),
            "--files", f"{sources}/passwd {secret}",
        )
        assert result.returncode == 2
        assert "cannot read" in result.stderr
        assert archive_list(backup_dir) == []

        partial = run_script(
            "--backup-dir", str(backup_dir),
            "--files", f"{sources}/passwd {secret}",
            "--allow-partial",
        )
        assert partial.returncode == 0, partial.stderr
        assert "unreadable" in partial.stderr
        assert len(archive_list(backup_dir)) == 1
    finally:
        secret.chmod(0o600)


def test_dry_run_writes_nothing(backup_dir, sources):
    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    assert "[dry-run]" in result.stdout
    assert "nothing was written" in result.stdout
    assert not backup_dir.exists()


def test_dry_run_does_not_prune(backup_dir, sources):
    for _ in range(2):
        assert run_script(
            "--backup-dir", str(backup_dir),
            "--files", f"{sources}/passwd",
            "--keep", "0",
        ).returncode == 0
    assert len(archive_list(backup_dir)) == 2

    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
        "--keep", "1",
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    assert len(archive_list(backup_dir)) == 2


def test_retention_keeps_the_newest_n(backup_dir, sources):
    """Seed three old archives, run once with --keep 2, and check the oldest goes."""
    backup_dir.mkdir(mode=0o700)
    for day in (1, 2, 3):
        archive = backup_dir / f"critical_configs_2020010{day}_000000.tar.gz"
        archive.write_bytes(b"placeholder")
        Path(str(archive) + ".sha256").write_text("placeholder\n")

    result = run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
        "--keep", "2",
    )
    assert result.returncode == 0, result.stderr

    names = [p.name for p in archive_list(backup_dir)]
    assert len(names) == 2
    # This run's archive plus the newest seeded one survive; the two oldest go.
    assert not any("20200101" in n for n in names)
    assert not any("20200102" in n for n in names)
    assert any("20200103" in n for n in names)
    # Pruning removes the sidecar alongside the archive.
    assert not Path(str(backup_dir / "critical_configs_20200101_000000.tar.gz") + ".sha256").exists()
    for name in names:
        assert Path(str(backup_dir / name) + ".sha256").exists()


def test_retention_zero_keeps_everything(backup_dir, sources):
    for _ in range(3):
        assert run_script(
            "--backup-dir", str(backup_dir),
            "--files", f"{sources}/passwd",
            "--keep", "0",
        ).returncode == 0
    assert len(archive_list(backup_dir)) == 3


def test_same_second_runs_do_not_overwrite(backup_dir, sources):
    for _ in range(3):
        result = run_script(
            "--backup-dir", str(backup_dir),
            "--files", f"{sources}/passwd",
            "--keep", "0",
        )
        assert result.returncode == 0, result.stderr
    assert len(archive_list(backup_dir)) == 3


def test_no_temporary_files_left_behind(backup_dir, sources):
    assert run_script(
        "--backup-dir", str(backup_dir),
        "--files", f"{sources}/passwd",
    ).returncode == 0
    leftovers = [p.name for p in backup_dir.iterdir() if p.name.startswith(".")]
    assert leftovers == []
