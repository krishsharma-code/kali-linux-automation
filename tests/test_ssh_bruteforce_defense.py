"""Tests for bash_scripts/ssh_bruteforce_defense.sh.

The script is exercised through its real command line, against a throwaway
auth log and a stub ``ufw`` on ``PATH``, so the tests never touch the host
firewall and never need root for the reporting path.

The properties that matter are the security ones:

* the source address is recovered from a log line by pattern, not by token
  position, so a line with an extra word cannot shift a username into the
  firewall ruleset;
* a candidate that is not a real IPv4 address is dropped before it is
  reported or passed to ``ufw``;
* the default run is read-only and only ``--apply`` changes firewall state;
* "already denied" is an exact address match, so 203.0.113.7 is not treated
  as blocked just because 203.0.113.70 is in the ruleset.

The ``--apply`` path needs a uid of 0 for its privilege gate, so those tests
re-run the script inside a throwaway user namespace and skip where user
namespaces are unavailable.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "bash_scripts" / "ssh_bruteforce_defense.sh"

BELOW_THRESHOLD = "203.0.113.200"
OFFENDER = "203.0.113.7"
OFFENDER_NEIGHBOUR = "203.0.113.70"

UFW_STUB = """#!/usr/bin/env bash
# Stub ufw: record every call, answer "status" from $UFW_STATUS_FILE.
printf '%s\\n' "$*" >> "$UFW_CALLS_FILE"
if [[ "${1:-}" == "status" ]]; then
    [[ -f "$UFW_STATUS_FILE" ]] && cat "$UFW_STATUS_FILE"
    exit 0
fi
exit "${UFW_EXIT_CODE:-0}"
"""


def run_script(*args, env=None, cwd=None):
    """Run the script with a clean environment and return the completed process."""
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    if env:
        base_env.update(env)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=base_env,
        cwd=str(cwd) if cwd else None,
        check=False,
    )


def unshare_available():
    """True when we can run the script with uid 0 inside a user namespace."""
    if not shutil.which("unshare"):
        return False
    probe = subprocess.run(
        ["unshare", "--user", "--map-root-user", "id", "-u"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and probe.stdout.strip() == "0"


requires_root_namespace = pytest.mark.skipif(
    not unshare_available(),
    reason="unprivileged user namespaces are unavailable; --apply needs uid 0",
)


def run_as_root(*args, env=None):
    """Run the script under a user namespace so the uid-0 gate is satisfied."""
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    if env:
        base_env.update(env)
    return subprocess.run(
        ["unshare", "--user", "--map-root-user", "bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=base_env,
        check=False,
    )


@pytest.fixture()
def fake_ufw(tmp_path):
    """A stub ufw on PATH that records its calls instead of changing rules."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "ufw"
    stub.write_text(UFW_STUB)
    stub.chmod(0o755)

    calls = tmp_path / "ufw_calls.txt"
    status = tmp_path / "ufw_status.txt"
    calls.write_text("")

    def env(extra=None):
        base = {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "UFW_CALLS_FILE": str(calls),
            "UFW_STATUS_FILE": str(status),
        }
        if extra:
            base.update(extra)
        return base

    def call_lines():
        return [line for line in calls.read_text().splitlines() if line.strip()]

    def deny_lines():
        return [line for line in call_lines() if line.startswith("insert")]

    fake = type("FakeUfw", (), {})()
    fake.bin_dir = bin_dir
    fake.calls = calls
    fake.status = status
    fake.env = staticmethod(env)
    fake.call_lines = staticmethod(call_lines)
    fake.deny_lines = staticmethod(deny_lines)
    return fake


@pytest.fixture()
def auth_log(tmp_path):
    """An auth log with one clear offender, one near-threshold IP and noise."""
    lines = [
        # Plain root attempts: three for the offender at the default threshold of 5.
        "Jan  1 00:00:01 host sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
        "Jan  1 00:00:02 host sshd[2]: Failed password for root from 203.0.113.7 port 22 ssh2",
        "Jan  1 00:00:02 host sshd[7]: Failed password for root from 203.0.113.7 port 22 ssh2",
        # The "invalid user" variant puts two extra tokens before the address.
        "Jan  1 00:00:03 host sshd[3]: Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
        "Jan  1 00:00:04 host sshd[4]: Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
        # Below threshold.
        f"Jan  1 00:00:05 host sshd[5]: Failed password for root from {BELOW_THRESHOLD} port 22 ssh2",
        # Accepted logins must not be counted.
        f"Jan  1 00:00:06 host sshd[6]: Accepted password for root from {BELOW_THRESHOLD} port 22 ssh2",
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n")
    return log


# --------------------------------------------------------------------------
# Invocation and argument handling
# --------------------------------------------------------------------------

def test_script_exists_and_is_syntactically_valid():
    assert SCRIPT.is_file()
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_help_exits_zero_and_touches_nothing(fake_ufw, tmp_path):
    result = run_script("--help", env=fake_ufw.env())
    assert result.returncode == 0
    assert "ssh_bruteforce_defense.sh" in result.stdout
    assert "--apply" in result.stdout
    assert fake_ufw.call_lines() == []


def test_unknown_option_is_a_usage_error(fake_ufw):
    result = run_script("--nope", env=fake_ufw.env())
    assert result.returncode == 1
    assert "unknown option" in result.stderr
    assert fake_ufw.call_lines() == []


def test_non_numeric_threshold_is_rejected(fake_ufw, auth_log):
    result = run_script("--threshold", "many", "--log", str(auth_log), env=fake_ufw.env())
    assert result.returncode == 1
    assert "non-negative integer" in result.stderr
    assert fake_ufw.call_lines() == []


def test_option_without_a_value_is_a_usage_error(fake_ufw):
    result = run_script("--log", env=fake_ufw.env())
    assert result.returncode == 1
    assert "--log needs a file argument" in result.stderr


def test_missing_log_file_fails_loudly(fake_ufw, tmp_path):
    missing = tmp_path / "nope.log"
    result = run_script("--log", str(missing), env=fake_ufw.env())
    assert result.returncode == 1
    assert "log file not found" in result.stderr
    assert fake_ufw.call_lines() == []


# --------------------------------------------------------------------------
# Reporting path (read-only)
# --------------------------------------------------------------------------

def test_default_run_reports_without_touching_the_firewall(fake_ufw, auth_log):
    result = run_script("--log", str(auth_log), env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert OFFENDER in result.stdout
    assert "5 failed attempts" in result.stdout
    # Nothing was denied, and ufw was never even consulted.
    assert fake_ufw.deny_lines() == []
    assert fake_ufw.call_lines() == []


def test_explicit_dry_run_matches_the_default(fake_ufw, auth_log):
    result = run_script("--log", str(auth_log), "--dry-run", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert "Report only" in result.stdout
    assert fake_ufw.deny_lines() == []


def test_below_threshold_address_is_not_reported(fake_ufw, auth_log):
    result = run_script("--log", str(auth_log), env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert BELOW_THRESHOLD not in result.stdout


def test_threshold_is_configurable(fake_ufw, auth_log):
    result = run_script("--log", str(auth_log), "--threshold", "1", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert BELOW_THRESHOLD in result.stdout
    assert "2 IP(s) at or above 1 attempts" in result.stdout


def test_clean_log_exits_zero_with_nothing_to_report(fake_ufw, tmp_path):
    log = tmp_path / "clean.log"
    log.write_text("Jan  1 00:00:01 host sshd[1]: Accepted publickey for root from 198.51.100.4 port 22 ssh2\n")
    result = run_script("--log", str(log), env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert "No failed password attempts found" in result.stdout
    assert fake_ufw.call_lines() == []


def test_state_file_is_written_owner_only(fake_ufw, auth_log, tmp_path):
    state = tmp_path / "state" / "blocked.txt"
    state.parent.mkdir()
    result = run_script(
        "--log", str(auth_log), "--state-file", str(state), env=fake_ufw.env()
    )
    assert result.returncode == 0, result.stderr
    assert state.is_file()
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    content = state.read_text()
    assert OFFENDER in content
    assert BELOW_THRESHOLD in content  # the ranked list keeps every address


# --------------------------------------------------------------------------
# Address extraction and validation
# --------------------------------------------------------------------------

def test_address_is_recovered_from_both_log_line_shapes(fake_ufw, auth_log):
    """The 'invalid user' form has two extra tokens; both must resolve to the IP."""
    result = run_script("--log", str(auth_log), "--threshold", "1", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert f"IP {OFFENDER} has 5 failed attempts" in result.stdout
    assert "admin" not in result.stdout


def test_out_of_range_octets_never_reach_the_firewall(fake_ufw, tmp_path):
    log = tmp_path / "bad.log"
    log.write_text(
        "Jan  1 00:00:01 host sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2\n"
        "Jan  1 00:00:02 host sshd[2]: Failed password for root from 999.1.1.1 port 22 ssh2\n"
        "Jan  1 00:00:03 host sshd[3]: Failed password for root from not-an-address port 22 ssh2\n"
    )
    result = run_script("--log", str(log), "--threshold", "1", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert "999.1.1.1" not in result.stdout
    assert "not-an-address" not in result.stdout
    assert fake_ufw.call_lines() == []


def test_free_text_tokens_are_never_treated_as_addresses(fake_ufw, tmp_path):
    """A log line whose trailing tokens are not an address must not be counted."""
    log = tmp_path / "odd.log"
    log.write_text(
        "Jan  1 00:00:01 host sshd[1]: Failed password for root from DISCONNECTED ssh2\n"
        "Jan  1 00:00:02 host sshd[2]: Failed password for root from DISCONNECTED ssh2\n"
    )
    result = run_script("--log", str(log), "--threshold", "1", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr
    assert "DISCONNECTED" not in result.stdout
    assert "No failed password attempts found" in result.stdout


# --------------------------------------------------------------------------
# Apply path (needs uid 0 for the privilege gate)
# --------------------------------------------------------------------------

def test_apply_without_root_is_refused(fake_ufw, auth_log):
    if os.geteuid() == 0:  # pragma: no cover - only when the suite runs as root
        pytest.skip("running as root; the refusal path cannot be observed")
    result = run_script("--log", str(auth_log), "--apply", env=fake_ufw.env())
    assert result.returncode == 3
    assert "must run as root" in result.stderr
    assert fake_ufw.deny_lines() == []


@requires_root_namespace
def test_apply_denies_only_addresses_at_or_above_threshold(fake_ufw, auth_log):
    result = run_as_root("--log", str(auth_log), "--apply", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr + result.stdout

    denies = fake_ufw.deny_lines()
    assert denies == [f"insert 1 deny from {OFFENDER} to any"]
    assert f"insert 1 deny from {BELOW_THRESHOLD} to any" not in denies
    assert "Newly denied: 1" in result.stdout


@requires_root_namespace
def test_apply_skips_an_already_denied_address(fake_ufw, auth_log):
    fake_ufw.status.write_text(f"{OFFENDER}   DENY IN   {OFFENDER}\n")
    result = run_as_root("--log", str(auth_log), "--apply", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr + result.stdout
    assert fake_ufw.deny_lines() == []
    assert "already denied" in result.stdout
    assert "Already denied: 1" in result.stdout


@requires_root_namespace
def test_already_denied_check_is_an_exact_match(fake_ufw, auth_log):
    """A neighbouring address in the ruleset must not mask the real offender."""
    fake_ufw.status.write_text(f"{OFFENDER_NEIGHBOUR}   DENY IN   {OFFENDER_NEIGHBOUR}\n")
    result = run_as_root("--log", str(auth_log), "--apply", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr + result.stdout
    assert fake_ufw.deny_lines() == [f"insert 1 deny from {OFFENDER} to any"]


@requires_root_namespace
def test_apply_reports_a_failing_denial(fake_ufw, auth_log):
    result = run_as_root(
        "--log", str(auth_log), "--apply", env=fake_ufw.env({"UFW_EXIT_CODE": "1"})
    )
    assert result.returncode == 1
    assert "ufw refused to deny" in result.stderr
    assert "Failed: 1" in result.stdout


@requires_root_namespace
def test_apply_queries_ufw_status_once_per_run(fake_ufw, tmp_path):
    """ufw status is cached: one call, not one per offending address."""
    log = tmp_path / "many.log"
    lines = []
    for index in range(4):
        address = f"198.51.100.{index + 10}"
        lines.extend(
            [f"Jan  1 00:00:0{index} host sshd[{index}]: Failed password for root from {address} port 22 ssh2"] * 5
        )
    log.write_text("\n".join(lines) + "\n")

    result = run_as_root("--log", str(log), "--apply", env=fake_ufw.env())
    assert result.returncode == 0, result.stderr + result.stdout
    status_calls = [line for line in fake_ufw.call_lines() if line.strip() == "status"]
    assert len(status_calls) == 1
    assert len(fake_ufw.deny_lines()) == 4
