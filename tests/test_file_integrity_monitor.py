"""Tests for bash_scripts/file_integrity_monitor.sh.

The script is exercised through its real command-line interface against
throwaway files in ``tmp_path``, so the tests never touch /etc and never need
root. What matters here is the security behaviour: the baseline must live in a
private location rather than a predictable shared /tmp path, it must not be
written through a symlink, a partial baseline must fail loudly, and each of the
three failure modes (modified, missing, unreadable) must be distinguishable.
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "bash_scripts" / "file_integrity_monitor.sh"


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
def watched(tmp_path):
    """Two small files standing in for the critical system files."""
    files = tmp_path / "watched"
    files.mkdir()
    passwd = files / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n")
    sudoers = files / "sudoers"
    sudoers.write_text("root ALL=(ALL:ALL) ALL\n")
    return files


@pytest.fixture()
def state(tmp_path):
    return tmp_path / "state"


def baseline(state):
    return state / "hashes.db"


def init_args(watched, state):
    return [
        "--init",
        "--files", f"{watched / 'passwd'} {watched / 'sudoers'}",
        "--state-dir", str(state),
    ]


def verify_args(watched, state):
    return [
        "--files", f"{watched / 'passwd'} {watched / 'sudoers'}",
        "--state-dir", str(state),
    ]


def test_script_exists_and_is_syntactically_valid():
    assert SCRIPT.is_file()
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_help_exits_zero_without_touching_the_filesystem(state):
    result = run_script("--help", "--state-dir", str(state))
    assert result.returncode == 0
    assert "file_integrity_monitor.sh" in result.stdout
    assert "--allow-partial" in result.stdout
    assert not state.exists()


def test_unknown_option_is_a_usage_error(state):
    result = run_script("--nope", "--state-dir", str(state))
    assert result.returncode == 2
    assert "unknown option" in result.stderr
    assert not state.exists()


def test_init_records_every_readable_file(watched, state):
    result = run_script(*init_args(watched, state))
    assert result.returncode == 0, result.stderr

    lines = baseline(state).read_text().splitlines()
    assert len(lines) == 2
    recorded = sorted(line.split("  ", 1)[1] for line in lines)
    assert recorded == sorted([str(watched / "passwd"), str(watched / "sudoers")])


def test_baseline_and_state_directory_are_owner_only(watched, state):
    assert run_script(*init_args(watched, state)).returncode == 0

    dir_mode = stat.S_IMODE(state.stat().st_mode)
    db_mode = stat.S_IMODE(baseline(state).stat().st_mode)
    assert dir_mode == 0o700, f"state dir mode is {oct(dir_mode)}"
    assert db_mode == 0o600, f"baseline mode is {oct(db_mode)}"


def test_existing_world_readable_state_directory_is_tightened(watched, state):
    state.mkdir()
    state.chmod(0o755)

    result = run_script(*init_args(watched, state))
    assert result.returncode == 0, result.stderr
    assert "tightening to 700" in result.stderr
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_reinit_does_not_append_duplicate_entries(watched, state):
    """The old script appended with >>, so every re-init grew the baseline."""
    for _ in range(3):
        assert run_script(*init_args(watched, state)).returncode == 0
    assert len(baseline(state).read_text().splitlines()) == 2


def test_verify_is_clean_after_init(watched, state):
    assert run_script(*init_args(watched, state)).returncode == 0
    result = run_script(*verify_args(watched, state))
    assert result.returncode == 0, result.stderr
    assert "[OK] All critical files are intact." in result.stdout


def test_first_verify_creates_a_baseline_instead_of_failing(watched, state):
    result = run_script(*verify_args(watched, state))
    assert result.returncode == 0, result.stderr
    assert "Baseline written" in result.stdout
    assert baseline(state).is_file()


def test_modified_file_is_reported_and_exits_one(watched, state):
    assert run_script(*init_args(watched, state)).returncode == 0

    (watched / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    result = run_script(*verify_args(watched, state))

    assert result.returncode == 1
    assert "MODIFIED" in result.stderr
    assert str(watched / "passwd") in result.stderr
    # The untouched file is not reported.
    assert str(watched / "sudoers") not in result.stderr


def test_deleted_file_is_reported_as_missing(watched, state):
    assert run_script(*init_args(watched, state)).returncode == 0

    (watched / "sudoers").unlink()
    result = run_script(*verify_args(watched, state))

    assert result.returncode == 1
    assert "MISSING" in result.stderr
    assert str(watched / "sudoers") in result.stderr


def test_unreadable_file_is_an_error_rather_than_a_violation(watched, state):
    """A permission change must not be misreported as a modified file."""
    assert run_script(*init_args(watched, state)).returncode == 0

    secret = watched / "sudoers"
    secret.chmod(0o000)
    if os.geteuid() == 0:
        pytest.skip("root can read a 0000 file, so the unreadable path cannot be simulated")
    try:
        result = run_script(*verify_args(watched, state))
        assert result.returncode == 2
        assert "UNREADABLE" in result.stderr
        assert "MODIFIED" not in result.stderr
    finally:
        secret.chmod(0o600)


def test_unreadable_file_fails_init_unless_partial_is_allowed(watched, state):
    secret = watched / "sudoers"
    secret.chmod(0o000)
    if os.geteuid() == 0:
        pytest.skip("root can read a 0000 file, so the unreadable path cannot be simulated")

    try:
        result = run_script(*init_args(watched, state))
        assert result.returncode == 2
        assert "could not be read" in result.stderr
        # Nothing was published: a partial baseline is worse than none.
        assert not baseline(state).exists()

        partial = run_script(*init_args(watched, state), "--allow-partial")
        assert partial.returncode == 0, partial.stderr
        recorded = baseline(state).read_text()
        assert str(watched / "passwd") in recorded
        assert str(secret) not in recorded
    finally:
        secret.chmod(0o600)


def test_symlinked_baseline_is_refused(watched, state, tmp_path):
    """The old /tmp path let a local user symlink the database anywhere."""
    state.mkdir(mode=0o700)
    target = tmp_path / "attacker-controlled.db"
    target.write_text("")
    os.symlink(target, baseline(state))

    result = run_script(*init_args(watched, state))
    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert target.read_text() == ""


def test_missing_file_at_init_is_skipped_with_a_warning(watched, state):
    result = run_script(
        "--init",
        "--files", f"{watched / 'passwd'} {watched / 'does_not_exist'}",
        "--state-dir", str(state),
    )
    assert result.returncode == 0, result.stderr
    assert "not present on this host" in result.stderr
    assert len(baseline(state).read_text().splitlines()) == 1


def test_no_readable_files_fails_without_writing_a_baseline(state, tmp_path):
    result = run_script(
        "--init",
        "--files", f"{tmp_path / 'missing_one'} {tmp_path / 'missing_two'}",
        "--state-dir", str(state),
    )
    assert result.returncode == 2
    assert "no readable files" in result.stderr
    assert not baseline(state).exists()


def test_paths_containing_spaces_round_trip(watched, state):
    spaced = watched / "with space.conf"
    spaced.write_text("PermitRootLogin no\n")

    # A multi-line --files value is read one path per line, which is the only
    # way to express a path containing a space through this interface.
    assert run_script(
        "--init", "--files", f"{spaced}\n{watched / 'passwd'}", "--state-dir", str(state)
    ).returncode == 0
    assert run_script(
        "--files", f"{spaced}\n{watched / 'passwd'}", "--state-dir", str(state)
    ).returncode == 0

    spaced.write_text("PermitRootLogin yes\n")
    result = run_script("--files", f"{spaced}\n{watched / 'passwd'}", "--state-dir", str(state))
    assert result.returncode == 1
    assert "MODIFIED" in result.stderr


def test_default_baseline_lives_under_xdg_state_home(watched, tmp_path):
    """Regression guard: the baseline must not default to a shared /tmp path."""
    xdg = tmp_path / "xdg"
    result = run_script("--init", "--files", str(watched / "passwd"), env={"XDG_STATE_HOME": str(xdg)})

    assert result.returncode == 0, result.stderr
    expected = xdg / "file-integrity-monitor" / "hashes.db"
    assert expected.is_file()
    assert stat.S_IMODE(expected.stat().st_mode) == 0o600
    assert not Path("/tmp/sys_file_hashes.db").exists()


def test_no_temporary_files_left_behind(watched, state):
    assert run_script(*init_args(watched, state)).returncode == 0
    leftovers = [p.name for p in state.iterdir() if p.name.startswith(".")]
    assert leftovers == []
