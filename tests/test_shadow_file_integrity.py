"""Tests for python_scripts/shadow_file_integrity.py.

Every case runs against a throwaway file in ``tmp_path``, never against the real
``/etc/shadow``, and never needs root: the script only calls ``lstat``, so the
tests assert on the permission, ownership and file-type findings while passing
the current user's UID/GID as the expected values.

The security-relevant behaviours pinned here are the ones the pre-refactor
script got wrong or could not express:

* special bits (``0o7000``) are inspected, not just the low permission bits,
  so a ``0o4600`` shadow file is reported instead of passing as "clean";
* a symlink is reported as critical rather than silently followed;
* a non-regular file is refused rather than treated as the shadow database;
* findings are returned in severity order and drive a non-zero exit code, so
  the script is usable from cron and CI.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import shadow_file_integrity as sfi

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "python_scripts" / "shadow_file_integrity.py"

CURRENT_UID = os.getuid()
CURRENT_GID = os.getgid()


def codes(findings):
    """Return the set of finding codes."""
    return {finding.code for finding in findings}


@pytest.fixture()
def shadow_file(tmp_path):
    """Create a private (0o600) shadow-like file owned by the current user."""
    path = tmp_path / "shadow"
    path.write_text("root:$6$abc$def:19000:0:99999:7:::\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def run_cli(*args):
    """Run the script as a subprocess and return the completed process."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


# --- audit() behaviour -------------------------------------------------------


def test_clean_file_produces_no_findings(shadow_file):
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert findings == []


def test_world_readable_is_critical(shadow_file):
    shadow_file.chmod(0o644)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert "SHADOW_WORLD_READABLE" in codes(findings)
    assert next(f for f in findings if f.code == "SHADOW_WORLD_READABLE").severity == "critical"


def test_world_writable_is_critical(shadow_file):
    shadow_file.chmod(0o666)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert "SHADOW_WORLD_WRITABLE" in codes(findings)


def test_group_writable_is_high(shadow_file):
    shadow_file.chmod(0o660)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    finding = next(f for f in findings if f.code == "SHADOW_GROUP_WRITABLE")
    assert finding.severity == "high"


def test_group_readable_is_informational(shadow_file):
    shadow_file.chmod(0o640)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert codes(findings) == {"SHADOW_GROUP_READABLE"}
    assert findings[0].severity == "info"


def test_setuid_bit_is_detected(shadow_file):
    """0o4600 previously passed every check because only 0o777 was examined."""
    shadow_file.chmod(0o4600)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert "SHADOW_SETUID" in codes(findings)


def test_setgid_bit_is_detected(shadow_file):
    shadow_file.chmod(0o2600)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert "SHADOW_SETGID" in codes(findings)


def test_sticky_bit_is_detected(shadow_file):
    shadow_file.chmod(0o1600)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    assert "SHADOW_STICKY" in codes(findings)


def test_wrong_owner_is_critical(shadow_file):
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID + 1, accepted_gids={CURRENT_GID})
    assert "SHADOW_BAD_OWNER" in codes(findings)


def test_unexpected_group_is_reported(shadow_file):
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID + 1})
    assert "SHADOW_BAD_GROUP" in codes(findings)


def test_symlink_is_reported_and_not_followed(tmp_path, shadow_file):
    """A symlink must never be followed: its target may be attacker-controlled."""
    link = tmp_path / "shadow-link"
    link.symlink_to(shadow_file)

    findings = sfi.audit(link, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})

    assert codes(findings) == {"SHADOW_SYMLINK"}
    assert findings[0].severity == "critical"


def test_directory_is_refused(tmp_path):
    directory = tmp_path / "not-a-shadow-file"
    directory.mkdir()

    findings = sfi.audit(directory, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})

    assert codes(findings) == {"SHADOW_NOT_REGULAR_FILE"}


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        sfi.audit(tmp_path / "absent", expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})


def test_findings_are_sorted_by_severity(shadow_file):
    shadow_file.chmod(0o4666)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID + 1, accepted_gids={CURRENT_GID + 1})

    ranks = [sfi.severity_rank(finding.severity) for finding in findings]
    assert ranks == sorted(ranks)
    assert findings[0].severity == "critical"


# --- remediation_hint() ------------------------------------------------------


def test_remediation_hint_is_empty_when_clean(shadow_file):
    assert sfi.remediation_hint(shadow_file, []) == ""


def test_remediation_hint_keeps_shadow_group_on_distro_default(shadow_file):
    """A group-readable 640 file must not be 'fixed' into root:root."""
    shadow_file.chmod(0o640)
    findings = sfi.audit(shadow_file, expected_uid=CURRENT_UID, accepted_gids={CURRENT_GID})
    hint = sfi.remediation_hint(Path("/etc/shadow"), findings)
    assert "chown root:shadow" in hint


def test_remediation_hint_uses_root_when_group_is_wrong(shadow_file):
    findings = [sfi.Finding("SHADOW_BAD_GROUP", "medium", "wrong group")]
    hint = sfi.remediation_hint(Path("/etc/shadow"), findings)
    assert "chown root:root" in hint


# --- command-line interface --------------------------------------------------


def test_cli_json_document_has_expected_shape(shadow_file):
    result = run_cli("--path", str(shadow_file), "--json", "--fail-on", "none")
    payload = json.loads(result.stdout)
    assert payload["path"] == str(shadow_file)
    assert set(payload["counts"]) == set(sfi.SEVERITIES)
    # The tests do not run as root, so the owner check always fires.
    assert payload["counts"]["critical"] >= 1


def test_cli_json_is_parseable_and_reports_counts(shadow_file):
    shadow_file.chmod(0o644)
    result = run_cli("--path", str(shadow_file), "--json")
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert {"SHADOW_WORLD_READABLE", "SHADOW_BAD_OWNER"} <= {f["code"] for f in payload["findings"]}
    assert payload["remediation"]


def test_cli_exits_one_when_threshold_met(shadow_file):
    shadow_file.chmod(0o644)
    assert run_cli("--path", str(shadow_file)).returncode == 1


def test_main_exit_code_follows_fail_on(monkeypatch, tmp_path):
    """--fail-on decides which severities are fatal, independent of the audit."""
    low_only = [sfi.Finding("SHADOW_GROUP_READABLE", "info", "informational")]
    monkeypatch.setattr(sfi, "audit", lambda path: list(low_only))
    target = str(tmp_path / "shadow")

    assert sfi.main(["--path", target, "--fail-on", "high", "--quiet"]) == 0
    assert sfi.main(["--path", target, "--fail-on", "info", "--quiet"]) == 1
    assert sfi.main(["--path", target, "--fail-on", "none", "--quiet"]) == 0


def test_main_exit_code_zero_when_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(sfi, "audit", lambda path: [])
    assert sfi.main(["--path", str(tmp_path / "shadow"), "--quiet"]) == 0


def test_main_reports_unreadable_path(monkeypatch, tmp_path, capsys):
    def boom(path):
        raise PermissionError("nope")

    monkeypatch.setattr(sfi, "audit", boom)
    assert sfi.main(["--path", str(tmp_path / "shadow")]) == 2
    assert "permission denied" in capsys.readouterr().err


def test_cli_missing_file_exits_two(tmp_path):
    result = run_cli("--path", str(tmp_path / "absent"))
    assert result.returncode == 2
    assert "not found" in result.stderr


def test_cli_quiet_prints_nothing(shadow_file):
    result = run_cli("--path", str(shadow_file), "--quiet", "--fail-on", "none")
    assert result.stdout == ""


def test_cli_help_lists_options():
    result = run_cli("--help")
    assert result.returncode == 0
    for flag in ("--path", "--json", "--fail-on", "--quiet"):
        assert flag in result.stdout


def test_script_is_not_world_writable():
    """The audit tool itself must not be a privilege-escalation vector."""
    mode = stat.S_IMODE(os.stat(SCRIPT).st_mode)
    assert not mode & stat.S_IWOTH
