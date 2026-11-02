"""Tests for python_scripts/malicious_ip_blocker.py.

Focus areas:
    * input validation - only real addresses and CIDRs survive parsing
    * command injection - a hostile block-list line must never reach the
      generated shell script
    * failure handling - unreadable input, unwritable output, empty results
    * the exit-code contract, the atomic write and the demo's isolation
"""

import stat

import pytest

import malicious_ip_blocker as blocker

# Block-list lines carrying shell metacharacters. The payloads stay benign on
# purpose: the point is that the separator survives into a root shell, not that
# the test can hurt the machine it runs on.
INJECTION_PAYLOADS = [
    "203.0.113.10; id",
    "203.0.113.10 && id",
    "$(id -u)",
    "203.0.113.10`whoami`",
    "203.0.113.10 | cat",
    "203.0.113.10\nid",
]


def _write_list(tmp_path, text, name="bad_ips.txt"):
    """Write a block list into ``tmp_path`` and return its path."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --- Entry parsing ----------------------------------------------------------

def test_parse_ip_entry_accepts_ipv4():
    assert blocker.parse_ip_entry("203.0.113.10") == "203.0.113.10"


def test_parse_ip_entry_trims_whitespace_and_trailing_comment():
    assert blocker.parse_ip_entry("  203.0.113.10  # ssh brute force\n") == "203.0.113.10"


def test_parse_ip_entry_accepts_ipv6():
    assert blocker.parse_ip_entry(" 2001:0db8:0000::0001 ") == "2001:db8::1"


def test_parse_ip_entry_normalises_cidr():
    assert blocker.parse_ip_entry("10.0.0.0/8") == "10.0.0.0/8"
    # A host address with a prefix is normalised to its network.
    assert blocker.parse_ip_entry("10.1.2.3/8") == "10.0.0.0/8"


@pytest.mark.parametrize("raw", ["", "   ", "# whole-line comment"])
def test_parse_ip_entry_rejects_blank_and_comment_lines(raw):
    assert blocker.parse_ip_entry(raw) is None


@pytest.mark.parametrize("raw", [
    "example.com",
    "203.0.113.256",
    "203.0.113",
    "10.0.0.0/33",
    "x" * 200,
])
def test_parse_ip_entry_rejects_malformed_values(raw):
    assert blocker.parse_ip_entry(raw) is None


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_parse_ip_entry_rejects_shell_metacharacters(payload):
    assert blocker.parse_ip_entry(payload) is None


# --- List loading -----------------------------------------------------------

def test_load_blocklist_deduplicates_and_preserves_order(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n192.0.2.5\n203.0.113.10\n")
    accepted, rejected = blocker.load_blocklist(source)
    assert accepted == ["203.0.113.10", "192.0.2.5"]
    assert rejected == []


def test_load_blocklist_reports_rejected_lines_with_numbers(tmp_path):
    source = _write_list(
        tmp_path, "203.0.113.10\nnot-an-ip\n\n192.0.2.5\n203.0.113.10; id\n")
    accepted, rejected = blocker.load_blocklist(source)
    assert accepted == ["203.0.113.10", "192.0.2.5"]
    assert [line for line, _ in rejected] == [2, 5]


def test_load_blocklist_raises_for_missing_file(tmp_path):
    with pytest.raises(blocker.BlocklistError):
        blocker.load_blocklist(tmp_path / "absent.txt")


def test_load_blocklist_raises_for_directory(tmp_path):
    with pytest.raises(blocker.BlocklistError):
        blocker.load_blocklist(tmp_path)


def test_load_blocklist_survives_undecodable_bytes(tmp_path):
    source = tmp_path / "bad_ips.txt"
    source.write_bytes(b"203.0.113.10\n\xff\xfe broken\n192.0.2.5\n")
    accepted, rejected = blocker.load_blocklist(source)
    assert accepted == ["203.0.113.10", "192.0.2.5"]
    assert len(rejected) == 1


# --- Script rendering -------------------------------------------------------

def test_render_block_script_emits_one_rule_per_entry():
    text = blocker.render_block_script(["203.0.113.10", "2001:db8::1"])
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert "sudo ufw deny from 203.0.113.10 to any" in text
    assert "sudo ufw deny from 2001:db8::1 to any" in text
    assert text.count("ufw deny") == 2


def test_render_block_script_with_no_entries_has_no_rules():
    text = blocker.render_block_script([])
    assert "ufw deny" not in text
    assert "No block rules to apply." in text


def test_render_block_script_flattens_source_name():
    text = blocker.render_block_script([], "evil\nsudo ufw disable")
    header = [line for line in text.splitlines() if line.startswith("# Source:")]
    assert header == ["# Source: evil sudo ufw disable"]


# --- Generation and writing -------------------------------------------------

def test_generate_writes_script_with_owner_only_permissions(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n192.0.2.5\n")
    output = tmp_path / "apply_blocks.sh"
    summary = blocker.generate_block_script(source, output)

    assert summary["written"] is True
    assert summary["output"] == output.resolve()
    assert output.read_text(encoding="utf-8") == summary["text"]

    mode = stat.S_IMODE(output.stat().st_mode)
    assert mode == 0o600
    # Not executable: the operator must invoke it deliberately via bash.
    assert not output.stat().st_mode & stat.S_IXUSR


def test_generate_leaves_no_staging_files_behind(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n")
    blocker.generate_block_script(source, tmp_path / "apply_blocks.sh")
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".blocklist-")] == []


def test_generate_overwrites_existing_output(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n")
    output = _write_list(tmp_path, "stale rule\n", name="apply_blocks.sh")
    blocker.generate_block_script(source, output)
    text = output.read_text(encoding="utf-8")
    assert "stale rule" not in text
    assert "203.0.113.10" in text


def test_generate_reports_unwritable_directory(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n")
    with pytest.raises(blocker.BlocklistError):
        blocker.generate_block_script(source, tmp_path / "missing" / "out.sh")


def test_generate_writes_nothing_when_no_entry_is_valid(tmp_path):
    source = _write_list(tmp_path, "not-an-ip\n203.0.113.10; id\n")
    output = tmp_path / "apply_blocks.sh"
    summary = blocker.generate_block_script(source, output)
    assert summary["written"] is False
    assert summary["accepted"] == []
    assert not output.exists()


def test_injection_payload_never_reaches_the_generated_script(tmp_path):
    # The multi-line payload splits into a valid address plus a junk line, so
    # only the single-line payloads can leave a list with nothing usable in it.
    single_line = [p for p in INJECTION_PAYLOADS if "\n" not in p]
    source = _write_list(tmp_path, "\n".join(single_line) + "\n")
    output = tmp_path / "apply_blocks.sh"
    summary = blocker.generate_block_script(source, output)

    assert summary["written"] is False
    assert not output.exists()

    # Now mix one good address in with the payloads and inspect the output.
    source = _write_list(
        tmp_path, "203.0.113.10\n" + "\n".join(INJECTION_PAYLOADS) + "\n")
    summary = blocker.generate_block_script(source, output)
    text = output.read_text(encoding="utf-8")

    assert summary["accepted"] == ["203.0.113.10"]
    assert len(summary["rejected"]) == len(INJECTION_PAYLOADS)

    # Only executable lines matter here: comment text may legitimately contain
    # punctuation such as the semicolon in the generated header.
    rule_lines = [line for line in text.splitlines() if line.startswith("sudo ufw")]
    assert rule_lines == ["sudo ufw deny from 203.0.113.10 to any"]
    for needle in (";", "$(", "&&", "|", "`", "whoami"):
        assert all(needle not in line for line in rule_lines)


def test_dry_run_writes_nothing(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n")
    output = tmp_path / "apply_blocks.sh"
    summary = blocker.generate_block_script(source, output, dry_run=True)
    assert summary["written"] is False
    assert summary["accepted"] == ["203.0.113.10"]
    assert "203.0.113.10" in summary["text"]
    assert not output.exists()


# --- CLI contract -----------------------------------------------------------

def test_main_generates_script_and_returns_zero(tmp_path):
    source = _write_list(tmp_path, "203.0.113.10\n")
    output = tmp_path / "apply_blocks.sh"
    assert blocker.main(["--input", str(source), "--output", str(output)]) == 0
    assert output.exists()


def test_main_requires_input(tmp_path, capsys):
    assert blocker.main([]) == 2
    assert "--input is required" in capsys.readouterr().err


def test_main_returns_two_for_missing_input(tmp_path, capsys):
    code = blocker.main(["--input", str(tmp_path / "absent.txt")])
    assert code == 2
    assert "cannot read" in capsys.readouterr().err


def test_main_returns_one_when_nothing_is_valid(tmp_path, capsys):
    source = _write_list(tmp_path, "nope\n")
    code = blocker.main(["--input", str(source),
                         "--output", str(tmp_path / "out.sh")])
    assert code == 1
    assert "No valid entries" in capsys.readouterr().err


def test_main_dry_run_prints_rules_and_writes_nothing(tmp_path, capsys):
    source = _write_list(tmp_path, "203.0.113.10\n")
    output = tmp_path / "apply_blocks.sh"
    code = blocker.main(["--input", str(source), "--output", str(output),
                         "--dry-run"])
    assert code == 0
    assert not output.exists()
    assert "sudo ufw deny from 203.0.113.10 to any" in capsys.readouterr().out


def test_main_reports_skipped_lines(tmp_path, capsys):
    source = _write_list(tmp_path, "203.0.113.10\nnot-an-ip\n")
    blocker.main(["--input", str(source), "--output", str(tmp_path / "out.sh")])
    assert "Skipped line 2" in capsys.readouterr().out


def test_main_help_exits_cleanly_and_writes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exit_info:
        blocker.main(["--help"])
    assert exit_info.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()
    assert list(tmp_path.iterdir()) == []


def test_main_demo_leaves_the_working_directory_untouched(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert blocker.main(["--demo"]) == 0
    assert list(tmp_path.iterdir()) == []
