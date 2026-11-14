"""Tests for python_scripts/subdomain_takeover_check.py.

Focus areas:
    * input validation - a host that could retarget the request is rejected
      before any URL is built
    * memory safety - the body is streamed and truncated at a byte cap
    * request hardening - redirects are not followed and a User-Agent is sent
    * failure isolation - one unreachable host must not abort the batch
    * the exit-code contract that makes the tool usable as a CI gate

No test touches the network; every request goes through a fake session.
"""

import io

import pytest
import requests

import subdomain_takeover_check as stc


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, status=404, body=b"", headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size=8192):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start:start + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeSession:
    """Records calls and replays one canned response or raises one error."""

    def __init__(self, response=None, error=None):
        self.response = response if response is not None else FakeResponse()
        self.error = error
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        if self.error is not None:
            raise self.error
        return self.response

    def close(self):
        self.closed = True


def _run(hosts, session, **kwargs):
    """Run the checker with output captured so tests stay quiet."""
    out = io.StringIO()
    findings = stc.check_subdomain_takeover(hosts, session=session, stream=out, **kwargs)
    return findings, out.getvalue()


# --- Input validation -------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("dev.example.com", "dev.example.com"),
    ("  DEV.Example.COM  ", "dev.example.com"),
    ("blog.example.com.", "blog.example.com"),
    ("host.example.com:8443", "host.example.com:8443"),
])
def test_normalize_host_accepts_valid_hosts(value, expected):
    assert stc.normalize_host(value) == expected


@pytest.mark.parametrize("value", [
    "",
    "   ",
    ".",
    None,
    123,
    "evil.com@internal.corp",       # userinfo retargets the request
    "user:pw@evil.com",
    "evil.com/admin",               # path
    "evil.com?next=1",              # query
    "evil.com#fragment",            # fragment
    "host example.com",             # embedded whitespace
    "evil.com\x00",                 # control character
    "a..b",                         # empty label
    "-leading-hyphen.com",
    "host.example.com:notaport",
    "x" * 300,                      # over-long
])
def test_normalize_host_rejects_unsafe_input(value):
    assert stc.normalize_host(value) is None


def test_build_url_defaults_to_https():
    assert stc.build_url("dev.example.com") == "https://dev.example.com"


# --- Request hardening ------------------------------------------------------

def test_fetch_body_does_not_follow_redirects():
    session = FakeSession()
    stc.fetch_body("https://dev.example.com", session=session)
    assert session.calls[0]["kwargs"]["allow_redirects"] is False


def test_fetch_body_sends_user_agent_and_streams():
    session = FakeSession()
    stc.fetch_body("https://dev.example.com", session=session)
    kwargs = session.calls[0]["kwargs"]
    assert kwargs["stream"] is True
    assert kwargs["headers"]["User-Agent"] == stc.DEFAULT_USER_AGENT


def test_fetch_body_truncates_at_byte_cap():
    payload = b"a" * 5000
    session = FakeSession(FakeResponse(body=payload))
    _, _, body, truncated = stc.fetch_body(
        "https://dev.example.com", session=session, max_bytes=1000
    )
    assert truncated is True
    assert len(body) == 1000


def test_fetch_body_reports_not_truncated_when_under_cap():
    session = FakeSession(FakeResponse(body=b"small"))
    _, _, body, truncated = stc.fetch_body(
        "https://dev.example.com", session=session, max_bytes=1000
    )
    assert truncated is False
    assert body == "small"


def test_fetch_body_replaces_undecodable_bytes():
    session = FakeSession(FakeResponse(body=b"ok \xff\xfe done"))
    _, _, body, _ = stc.fetch_body("https://dev.example.com", session=session)
    assert "ok " in body and "done" in body


# --- Detection --------------------------------------------------------------

def test_detects_s3_dangling_bucket_case_insensitively():
    body = b"<Error><Code>NoSuchBucket</Code></Error>"
    session = FakeSession(FakeResponse(status=404, body=body))
    findings, _ = _run(["bucket-test.s3.amazonaws.com"], session)
    assert [f["provider"] for f in findings] == ["Amazon S3"]
    assert findings[0]["status"] == 404


@pytest.mark.parametrize("body, provider", [
    (b"no such app", "Heroku"),
    (b"there isn't a GitHub Pages site here", "GitHub Pages"),
    (b"Sorry, this shop is currently unavailable", "Shopify"),
])
def test_detects_each_supported_provider(body, provider):
    session = FakeSession(FakeResponse(body=body))
    findings, _ = _run(["sub.example.com"], session)
    assert findings[0]["provider"] == provider


def test_clean_response_yields_no_findings():
    session = FakeSession(FakeResponse(status=200, body=b"<html>welcome</html>"))
    findings, output = _run(["dev.example.com"], session)
    assert findings == []
    assert "Secure" in output


def test_finding_records_location_header_for_triage():
    response = FakeResponse(status=301, body=b"NoSuchBucket",
                            headers={"Location": "https://s3.amazonaws.com/x"})
    session = FakeSession(response)
    findings, _ = _run(["sub.example.com"], session)
    assert findings[0]["location"] == "https://s3.amazonaws.com/x"


# --- Failure isolation ------------------------------------------------------

def test_invalid_host_is_skipped_without_a_request():
    session = FakeSession()
    findings, output = _run(["evil.com@internal.corp", "dev.example.com"], session)
    assert findings == []
    assert "Skipped invalid host" in output
    assert [c["url"] for c in session.calls] == ["https://dev.example.com"]


def test_request_error_does_not_abort_the_batch():
    session = FakeSession(error=requests.exceptions.ConnectionError("boom"))
    findings, output = _run(["a.example.com", "b.example.com"], session)
    assert findings == []
    assert output.count("connection failed") == 2


def test_empty_host_list_is_handled():
    session = FakeSession()
    findings, output = _run([], session)
    assert findings == []
    assert "Checking 0 subdomains" in output


# --- CLI / exit-code contract ----------------------------------------------

def test_main_returns_1_when_a_takeover_is_found(monkeypatch):
    monkeypatch.setattr(stc, "check_subdomain_takeover",
                        lambda hosts, **kwargs: [{"host": "a.example.com"}])
    assert stc.main(["a.example.com"]) == 1


def test_main_returns_0_when_clean(monkeypatch):
    monkeypatch.setattr(stc, "check_subdomain_takeover", lambda hosts, **kwargs: [])
    assert stc.main(["a.example.com"]) == 0


def test_main_returns_2_for_unreadable_hosts_file(capsys):
    assert stc.main(["--hosts-file", "/nonexistent/hosts.txt"]) == 2
    assert "Cannot read host list" in capsys.readouterr().err


def test_main_rejects_non_positive_limits():
    with pytest.raises(SystemExit) as excinfo:
        stc.main(["--timeout", "0", "a.example.com"])
    assert excinfo.value.code == 2


def test_hosts_file_comments_and_blanks_are_ignored(tmp_path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("# comment\n\ndev.example.com\n  blog.example.com  \n", encoding="utf-8")
    assert stc._read_hosts_file(hosts_file) == ["dev.example.com", "blog.example.com"]


def test_main_falls_back_to_default_targets(monkeypatch):
    seen = {}

    def fake(hosts, **kwargs):
        seen["hosts"] = list(hosts)
        return []

    monkeypatch.setattr(stc, "check_subdomain_takeover", fake)
    assert stc.main([]) == 0
    assert seen["hosts"] == stc.DEFAULT_TARGETS


def test_main_json_flag_emits_machine_readable_output(monkeypatch, capsys):
    monkeypatch.setattr(stc, "check_subdomain_takeover",
                        lambda hosts, **kwargs: [{"host": "a.example.com", "provider": "Heroku"}])
    stc.main(["--json", "a.example.com"])
    out = capsys.readouterr().out
    assert '"provider": "Heroku"' in out
