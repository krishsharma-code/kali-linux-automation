"""Tests for python_scripts/auth_log_parser.py.

Focus areas:
    * detection - OpenSSH and PAM failure formats, including "invalid user"
      lines that the previous token-split parser silently dropped
    * security boundaries - only validated IP literals are ever counted or
      printed, so a hostile username cannot reach the terminal
    * memory bounds - the address table and per-line length are capped
    * failure handling - missing files, directories, undecodable bytes
    * the exit-code contract (0 clean, 1 threshold reached, 2 unreadable)
"""

import auth_log_parser as parser

# Hostile input: a username carrying an ANSI clear-screen sequence.
ESCAPE_USERNAME = "root\x1b[2J\x1b[H"


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def _sshd(ip, user="root"):
    return f"May 28 10:00:01 kali sshd[1234]: Failed password for {user} from {ip} port 22 ssh2\n"


# --- Detection --------------------------------------------------------------

def test_counts_failed_password_attempts(tmp_path):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50") + _sshd("192.168.1.50"))
    counts, overflow = parser.count_failed_attempts(log)
    assert counts == {"192.168.1.50": 2}
    assert overflow == 0


def test_counts_invalid_user_lines(tmp_path):
    log = _write(tmp_path / "auth.log",
                 "May 28 10:06:20 kali sshd[1]: Failed password for invalid user oracle "
                 "from 203.0.113.5 port 22 ssh2\n")
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {"203.0.113.5": 1}


def test_counts_pam_authentication_failure(tmp_path):
    log = _write(tmp_path / "auth.log",
                 "May 28 10:07:00 kali login[1]: authentication failure; logname= uid=0 "
                 "euid=0 tty=ssh ruser= rhost=198.51.100.7\n")
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {"198.51.100.7": 1}


def test_accepted_logins_are_ignored(tmp_path):
    log = _write(tmp_path / "auth.log",
                 "May 28 10:02:10 kali sshd[1]: Accepted password for user1 from 192.168.1.10 "
                 "port 22 ssh2\n")
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {}


def test_normalises_ipv4_mapped_and_ipv6(tmp_path):
    log = _write(tmp_path / "auth.log",
                 _sshd("::ffff:192.168.1.50") + _sshd("2001:db8::1"))
    counts, _ = parser.count_failed_attempts(log)
    assert set(counts) == {"192.168.1.50", "2001:db8::1"}


# --- Security boundaries ----------------------------------------------------

def test_hostile_username_never_reaches_the_report(tmp_path, capsys):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50", user=ESCAPE_USERNAME))
    parser.parse_auth_log(log)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "192.168.1.50" in out


def test_non_ip_address_token_is_rejected():
    assert parser.normalise_address("\x1b[2J") is None
    assert parser.normalise_address("evil.example.com") is None
    assert parser.normalise_address("192.168.1.50:22") is None
    assert parser.normalise_address("") is None


def test_hostname_after_from_is_not_counted(tmp_path):
    # sshd can log a reverse-resolved hostname in some configurations; a name is
    # not an address and must not become a table key.
    log = _write(tmp_path / "auth.log", _sshd("attacker.example.com"))
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {}


def test_multiple_from_tokens_use_the_address_not_the_username(tmp_path):
    # The old parts.index('from') lookup picked the first "from", which can be
    # part of the username and yields the wrong token.
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50", user="from"))
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {"192.168.1.50": 1}


# --- Memory bounds ----------------------------------------------------------

def test_address_table_is_capped(tmp_path):
    lines = "".join(_sshd(f"10.0.{i // 256}.{i % 256}") for i in range(50))
    log = _write(tmp_path / "auth.log", lines)
    counts, overflow = parser.count_failed_attempts(log, max_addresses=10)
    assert len(counts) == 10
    assert overflow == 40


def test_overlong_line_is_truncated(tmp_path):
    long_user = "u" * 100_000
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50", user=long_user))
    counts, _ = parser.count_failed_attempts(log)
    # Truncated before the address, so the line simply does not match.
    assert counts == {}


def test_overflow_is_reported(tmp_path, capsys):
    lines = "".join(_sshd(f"10.0.{i // 256}.{i % 256}") for i in range(20))
    log = _write(tmp_path / "auth.log", lines)
    counts, overflow = parser.count_failed_attempts(log, max_addresses=5)
    parser.report(counts, overflow, out=None)
    out = capsys.readouterr().out
    assert "untracked addresses" in out


# --- Failure handling -------------------------------------------------------

def test_missing_log_returns_none(tmp_path, capsys):
    assert parser.parse_auth_log(tmp_path / "nope.log") is None
    assert "cannot read log" in capsys.readouterr().out


def test_directory_as_log_is_handled(tmp_path, capsys):
    assert parser.parse_auth_log(tmp_path) is None
    assert "cannot read log" in capsys.readouterr().out


def test_undecodable_bytes_do_not_abort_the_run(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(b"\xff\xfe garbage \n" + _sshd("192.168.1.50").encode())
    counts, _ = parser.count_failed_attempts(log)
    assert counts == {"192.168.1.50": 1}


# --- Reporting --------------------------------------------------------------

def test_rank_attempts_orders_by_count_then_address():
    ranked = parser.rank_attempts({"b": 1, "a": 1, "c": 3})
    assert ranked == [("c", 3), ("a", 1), ("b", 1)]


def test_report_marks_threshold_as_critical(tmp_path, capsys):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50") * 4)
    parser.parse_auth_log(log, threshold=4)
    out = capsys.readouterr().out
    assert "[CRITICAL] IP: 192.168.1.50 | Failed Attempts: 4" in out


def test_top_limits_the_report(tmp_path, capsys):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50") * 2 + _sshd("192.168.1.60"))
    parser.parse_auth_log(log, top=1)
    out = capsys.readouterr().out
    assert "192.168.1.50" in out
    assert "192.168.1.60" not in out


def test_empty_log_reports_nothing_matched(tmp_path, capsys):
    log = _write(tmp_path / "auth.log", "")
    assert parser.parse_auth_log(log) == {}
    assert "No failed authentication attempts matched." in capsys.readouterr().out


# --- Demo data --------------------------------------------------------------

def test_demo_log_is_written_once(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = parser.write_demo_log("mock_auth.log")
    assert path.exists()
    counts, _ = parser.count_failed_attempts(path)
    assert counts["192.168.1.50"] == 3
    assert counts["203.0.113.5"] == 2


def test_demo_log_never_overwrites_an_existing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "mock_auth.log", "real data\n")
    try:
        parser.write_demo_log("mock_auth.log")
    except FileExistsError:
        pass
    else:
        raise AssertionError("expected FileExistsError")
    assert (tmp_path / "mock_auth.log").read_text() == "real data\n"


# --- Exit-code contract -----------------------------------------------------

def test_main_returns_one_when_threshold_reached(tmp_path, capsys):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50") * 3)
    assert parser.main(["--log", str(log), "--threshold", "3"]) == 1


def test_main_returns_zero_below_threshold(tmp_path):
    log = _write(tmp_path / "auth.log", _sshd("192.168.1.50"))
    assert parser.main(["--log", str(log), "--threshold", "3"]) == 0


def test_main_returns_two_for_missing_log(tmp_path):
    assert parser.main(["--log", str(tmp_path / "nope.log")]) == 2


def test_main_rejects_non_positive_threshold(tmp_path):
    try:
        parser.main(["--log", str(tmp_path / "auth.log"), "--threshold", "0"])
    except SystemExit as exit_error:
        assert exit_error.code == 2
    else:
        raise AssertionError("expected SystemExit")
