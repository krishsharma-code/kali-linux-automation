"""Tests for python_scripts/api_key_leak_scanner.py.

Focus areas:
    * detection of the supported credential signatures
    * redaction - a matched secret must never appear in the output
    * failure handling - bad paths, binary files and oversized files
    * the exit-code contract that makes the scanner usable as a CI gate
"""

import api_key_leak_scanner as scanner

# Well-known, non-functional example credentials (these are not real secrets).
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "A" * 36
GOOGLE_KEY = "AIza" + "B" * 35
SLACK_TOKEN = "xoxb-" + "1" * 12


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


# --- Detection --------------------------------------------------------------

def test_scan_file_detects_aws_key(tmp_path):
    target = _write(tmp_path / "config.py", f'aws_access_key = "{AWS_KEY}"\n')
    findings = scanner.scan_file(target)
    assert len(findings) == 1
    assert findings[0]["name"] == "AWS Access Key"
    assert findings[0]["line"] == 1


def test_scan_file_detects_generic_api_key(tmp_path):
    target = _write(tmp_path / "settings.txt", 'api_key = "abcdef1234567890XYZ"\n')
    findings = scanner.scan_file(target)
    assert [f["name"] for f in findings] == ["Generic API Key"]


def test_scan_file_detects_github_token(tmp_path):
    target = _write(tmp_path / "ci.sh", f'export TOKEN={GITHUB_TOKEN}\n')
    names = {f["name"] for f in scanner.scan_file(target)}
    assert "GitHub Personal Access Token" in names


def test_scan_file_detects_google_and_slack_keys(tmp_path):
    target = _write(tmp_path / "keys.env",
                    f"GOOGLE={GOOGLE_KEY}\nSLACK={SLACK_TOKEN}\n")
    names = {f["name"] for f in scanner.scan_file(target)}
    assert {"Google API Key", "Slack Token"} <= names


def test_scan_directory_finds_secrets_in_nested_files(tmp_path):
    nested = tmp_path / "pkg" / "deep"
    nested.mkdir(parents=True)
    _write(nested / "creds.py", f'key = "{AWS_KEY}"\n')
    findings = scanner.scan_directory(tmp_path)
    assert any(f["name"] == "AWS Access Key" for f in findings)


def test_clean_directory_has_no_findings(tmp_path):
    _write(tmp_path / "ok.py", "print('nothing to see here')\n")
    assert scanner.scan_directory(tmp_path) == []


# --- Redaction --------------------------------------------------------------

def test_scan_file_redacts_the_secret(tmp_path):
    target = _write(tmp_path / "config.py", f'aws_access_key = "{AWS_KEY}"\n')
    snippet = scanner.scan_file(target)[0]["snippet"]
    assert AWS_KEY not in snippet
    assert scanner.REDACTION_MARKER in snippet


def test_mask_line_removes_only_the_secret():
    pattern = scanner.SECRET_PATTERNS["AWS Access Key"]
    line = f'access_key = "{AWS_KEY}"  # do not commit\n'
    match = pattern.search(line)
    masked = scanner.mask_line(line, match)
    assert AWS_KEY not in masked
    assert "do not commit" in masked


# --- Skip rules and failure handling ---------------------------------------

def test_binary_file_is_skipped(tmp_path):
    target = tmp_path / "blob.py"
    target.write_bytes(b"\x00\x01\x02" + AWS_KEY.encode())
    assert scanner.scan_file(target) == []


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    target = _write(tmp_path / "big.txt", "x")
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 0)
    assert scanner.scan_file(target) == []


def test_skipped_extension_is_ignored(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(AWS_KEY.encode())
    assert scanner.scan_file(target) == []


def test_git_directory_is_skipped(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    _write(git_dir / "config", f'key = "{AWS_KEY}"\n')
    assert scanner.scan_directory(tmp_path) == []


def test_hidden_env_file_is_still_scanned(tmp_path):
    _write(tmp_path / ".env", f'API_KEY="{AWS_KEY}"\n')
    findings = scanner.scan_directory(tmp_path)
    assert any(f["name"] == "AWS Access Key" for f in findings)


# --- Exit-code contract -----------------------------------------------------

def test_main_returns_one_when_a_secret_is_found(tmp_path, capsys):
    _write(tmp_path / "a.py", f'key = "{AWS_KEY}"\n')
    assert scanner.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "LEAK DETECTED" in out
    assert AWS_KEY not in out


def test_main_returns_zero_for_a_clean_tree(tmp_path):
    _write(tmp_path / "a.py", "print('clean')\n")
    assert scanner.main([str(tmp_path)]) == 0


def test_main_returns_two_for_a_missing_directory(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    assert scanner.main([str(missing)]) == 2
    assert "is not a directory" in capsys.readouterr().out


def test_main_defaults_to_current_directory(tmp_path, monkeypatch, capsys):
    _write(tmp_path / "a.py", f'key = "{AWS_KEY}"\n')
    monkeypatch.chdir(tmp_path)
    assert scanner.main([]) == 1
