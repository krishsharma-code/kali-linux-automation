"""Tests for python_scripts/mac_address_spoof_automator.py.

Focus areas:
    * MAC generation - valid, locally administered, multicast bit clear
    * input validation - MAC and interface names, including trailing junk
    * state safety - the interface is always brought back up, even on failure
    * the exit-code contract used by callers and CI
"""

import pytest

import mac_address_spoof_automator as mac


def _noop_run(*args, **kwargs):
    """A subprocess.run stand-in that succeeds without running anything."""
    return None


# --- MAC generation ---------------------------------------------------------

def test_get_random_mac_is_valid():
    assert mac.is_valid_mac(mac.get_random_mac())


def test_get_random_mac_is_locally_administered_and_unicast():
    for _ in range(20):
        first_octet = int(mac.get_random_mac().split(":")[0], 16)
        assert first_octet & 0x02, "locally administered bit must be set"
        assert not first_octet & 0x01, "multicast bit must be clear"


# --- Validation -------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "aa:bb:cc:dd:ee:ff",
    "AA:BB:CC:DD:EE:FF",
    "00:00:00:00:00:00",
])
def test_is_valid_mac_accepts_good_addresses(value):
    assert mac.is_valid_mac(value)


@pytest.mark.parametrize("value", [
    "",
    "aa:bb:cc:dd:ee",           # too short
    "aa:bb:cc:dd:ee:ff:00",     # too long
    "aa:bb:cc:dd:ee:ff:zz",     # trailing junk after a full address
    "aa:bb:cc:dd:ee:ff00",      # trailing junk with no separator
    "aabbccddeeff",             # no separators
    "gg:bb:cc:dd:ee:ff",        # non-hex octet
])
def test_is_valid_mac_rejects_bad_addresses(value):
    assert not mac.is_valid_mac(value)


@pytest.mark.parametrize("value", ["eth0", "wlan0", "enp3s0", "br-abc123"])
def test_is_valid_interface_accepts_common_names(value):
    assert mac.is_valid_interface(value)


@pytest.mark.parametrize("value", [
    "",
    "-x",                 # would be read as an option by `ip`
    "eth 0",              # whitespace
    "a" * 16,             # longer than IFNAMSIZ-1
    "eth0;rm -rf /",      # shell metacharacters
])
def test_is_valid_interface_rejects_unsafe_names(value):
    assert not mac.is_valid_interface(value)


# --- change_mac -------------------------------------------------------------

def test_change_mac_dry_run_makes_no_calls(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(mac.subprocess, "run", lambda *a, **k: calls.append(a))
    assert mac.change_mac("eth0", "aa:bb:cc:dd:ee:ff", dry_run=True) is True
    assert calls == []
    assert "Dry run" in capsys.readouterr().out


def test_change_mac_runs_three_commands_on_success(monkeypatch):
    seen = []
    monkeypatch.setattr(mac.subprocess, "run", lambda cmd, **k: seen.append(cmd))
    assert mac.change_mac("eth0", "aa:bb:cc:dd:ee:ff") is True
    assert seen == [
        ["ip", "link", "set", "eth0", "down"],
        ["ip", "link", "set", "eth0", "address", "aa:bb:cc:dd:ee:ff"],
        ["ip", "link", "set", "eth0", "up"],
    ]


def test_change_mac_restores_interface_up_after_failure(monkeypatch):
    seen = []

    def fake_run(cmd, check=True):
        seen.append(cmd)
        # Fail the address-assignment step, as the kernel would on a bad MAC.
        if "address" in cmd:
            raise mac.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(mac.subprocess, "run", fake_run)
    assert mac.change_mac("eth0", "aa:bb:cc:dd:ee:ff") is False
    # The interface must still be brought back up despite the failure.
    assert ["ip", "link", "set", "eth0", "up"] == seen[-1]


def test_change_mac_reports_failure(monkeypatch, capsys):
    def fake_run(cmd, check=True):
        raise mac.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(mac.subprocess, "run", fake_run)
    assert mac.change_mac("eth0", "aa:bb:cc:dd:ee:ff") is False
    assert "Failed to change MAC" in capsys.readouterr().out


# --- main / CLI contract ----------------------------------------------------

def test_main_rejects_invalid_interface(capsys):
    assert mac.main(["eth 0", "aa:bb:cc:dd:ee:ff"]) == 1
    assert "Invalid interface name" in capsys.readouterr().out


def test_main_rejects_invalid_mac(capsys):
    assert mac.main(["eth0", "not-a-mac"]) == 1
    assert "Invalid MAC address format" in capsys.readouterr().out


def test_main_requires_root_for_real_run(monkeypatch, capsys):
    monkeypatch.setattr(mac.os, "geteuid", lambda: 1000)
    assert mac.main(["eth0", "aa:bb:cc:dd:ee:ff"]) == 1
    assert "root privileges" in capsys.readouterr().out


def test_main_dry_run_does_not_require_root(monkeypatch, capsys):
    monkeypatch.setattr(mac.os, "geteuid", lambda: 1000)
    assert mac.main(["eth0", "aa:bb:cc:dd:ee:ff", "--dry-run"]) == 0
    assert "Dry run" in capsys.readouterr().out


def test_main_success_path(monkeypatch):
    monkeypatch.setattr(mac.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mac.shutil, "which", lambda name: "/sbin/ip")
    monkeypatch.setattr(mac.subprocess, "run", _noop_run)
    assert mac.main(["eth0", "aa:bb:cc:dd:ee:ff"]) == 0


def test_main_generates_a_mac_when_omitted(monkeypatch):
    monkeypatch.setattr(mac.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mac.shutil, "which", lambda name: "/sbin/ip")
    seen = []
    monkeypatch.setattr(mac.subprocess, "run", lambda cmd, **k: seen.append(cmd))
    assert mac.main(["eth0"]) == 0
    assigned = seen[1][5]  # ["ip", "link", "set", "eth0", "address", <mac>]
    assert mac.is_valid_mac(assigned)


def test_main_errors_when_ip_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(mac.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mac.shutil, "which", lambda name: None)
    assert mac.main(["eth0", "aa:bb:cc:dd:ee:ff"]) == 1
    assert "'ip' command" in capsys.readouterr().out


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        mac.main(["--help"])
    assert exc.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()
