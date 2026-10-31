"""Tests for python_scripts/systemd_service_auditor.py.

Focus areas:
    * parsing of ``systemctl`` output, including blank lines, the ``●`` bullet
      marker and unit names that must not reach a subprocess
    * the trust boundary around unit names (no shell, validated names)
    * path classification - component boundaries and symlink resolution, the
      two places where a naive ``str.startswith``/``in`` check goes wrong
    * failure handling - missing systemctl, timeouts, non-zero exits, and a
      single unreadable unit not aborting the whole audit
    * the exit-code contract used by CI
"""

import json

import pytest

import systemd_service_auditor as auditor

# --- Fakes ------------------------------------------------------------------


class FakeSystemctl:
    """Stands in for ``auditor._run_systemctl``.

    ``responses`` maps the first systemctl argument to either a string
    (returned as stdout) or an exception instance to raise.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, args, timeout=auditor.DEFAULT_TIMEOUT):
        self.calls.append(list(args))
        key = args[0]
        if key not in self.responses:
            raise AssertionError(f"unexpected systemctl call: {args}")
        value = self.responses[key]
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value(args)
        return value


@pytest.fixture
def fake(monkeypatch):
    def install(responses):
        stub = FakeSystemctl(responses)
        monkeypatch.setattr(auditor, "_run_systemctl", stub)
        return stub

    return install


# --- list_running_services --------------------------------------------------

def test_list_running_services_parses_names(fake):
    fake({"list-units": "cron.service loaded active running Regular background\n"
                        "ssh.service loaded active running OpenBSD Secure Shell\n"})
    assert auditor.list_running_services() == ["cron.service", "ssh.service"]


def test_list_running_services_skips_blank_and_bullet_lines(fake):
    fake({"list-units": "\n\u25cf broken.service loaded failed failed Broken\n"
                        "   \nsshd.service loaded active running ssh\n"})
    assert auditor.list_running_services() == ["broken.service", "sshd.service"]


def test_list_running_services_drops_malformed_names(fake):
    fake({"list-units": "evil;rm -rf /.service loaded active running nope\n"
                        "good.service loaded active running fine\n"})
    assert auditor.list_running_services() == ["good.service"]


def test_list_running_services_requests_plain_output(fake):
    stub = fake({"list-units": ""})
    auditor.list_running_services()
    assert "--plain" in stub.calls[0]
    assert "--no-legend" in stub.calls[0]


def test_list_running_services_propagates_audit_error(fake):
    fake({"list-units": auditor.AuditError("systemctl list-units exited 1")})
    with pytest.raises(auditor.AuditError):
        auditor.list_running_services()


def test_list_running_services_raises_on_nonzero_exit(fake):
    fake({"list-units": auditor.AuditError("systemctl list-units exited 1: no bus")})
    with pytest.raises(auditor.AuditError):
        auditor.list_running_services()


# --- _run_systemctl ---------------------------------------------------------

def test_run_systemctl_reports_nonzero_exit(monkeypatch):
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "Failed to connect to bus\n"

    monkeypatch.setattr(auditor.subprocess, "run", lambda *a, **kw: Completed())
    with pytest.raises(auditor.AuditError, match="Failed to connect to bus"):
        auditor._run_systemctl(["list-units"])


def test_run_systemctl_translates_missing_binary(monkeypatch):
    def raise_missing(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(auditor.subprocess, "run", raise_missing)
    with pytest.raises(auditor.AuditError, match="systemctl not found"):
        auditor._run_systemctl(["list-units"])


def test_run_systemctl_translates_timeout(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise auditor.subprocess.TimeoutExpired("systemctl", 5)

    monkeypatch.setattr(auditor.subprocess, "run", raise_timeout)
    with pytest.raises(auditor.AuditError, match="timed out after 5"):
        auditor._run_systemctl(["list-units"], timeout=5)


def test_run_systemctl_translates_os_error(monkeypatch):
    def raise_oserror(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(auditor.subprocess, "run", raise_oserror)
    with pytest.raises(auditor.AuditError, match="could not execute systemctl"):
        auditor._run_systemctl(["list-units"])


def test_run_systemctl_passes_argv_without_shell(monkeypatch):
    captured = {}

    class Completed:
        returncode = 0
        stdout = "FragmentPath=/etc/systemd/system/x.service\n"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(auditor.subprocess, "run", fake_run)
    auditor._run_systemctl(["show", "x.service", "--property=FragmentPath"])
    assert captured["argv"] == ["systemctl", "show", "x.service", "--property=FragmentPath"]
    assert "shell" not in captured["kwargs"]
    assert captured["kwargs"]["timeout"] == auditor.DEFAULT_TIMEOUT


# --- get_fragment_path ------------------------------------------------------

def test_get_fragment_path_parses_property(fake):
    fake({"show": "FragmentPath=/etc/systemd/system/cron.service\n"})
    assert auditor.get_fragment_path("cron.service") == "/etc/systemd/system/cron.service"


def test_get_fragment_path_empty_value_is_none(fake):
    fake({"show": "FragmentPath=\n"})
    assert auditor.get_fragment_path("cron.service") is None


def test_get_fragment_path_missing_property_is_none(fake):
    fake({"show": ""})
    assert auditor.get_fragment_path("cron.service") is None


def test_get_fragment_path_rejects_malformed_name(fake):
    stub = fake({})
    with pytest.raises(ValueError, match="malformed unit name"):
        auditor.get_fragment_path("evil service")
    assert stub.calls == []


# --- classify_path ----------------------------------------------------------

def test_classify_standard_path_returns_none():
    assert auditor.classify_path("cron.service", "/lib/systemd/system/cron.service") is None


def test_classify_standard_path_under_usr_lib():
    assert auditor.classify_path("a.service", "/usr/lib/systemd/system/a.service") is None


def test_classify_prefix_boundary_is_not_standard():
    """Regression: '/lib/systemd/system-evil' must not pass a startswith() check."""
    finding = auditor.classify_path("x.service", "/lib/systemd/system-evil/x.service")
    assert finding is not None
    assert finding.reason == "non-standard-path"
    assert finding.severity == auditor.SEVERITY_WARNING


def test_classify_substring_is_not_high_risk():
    """Regression: '/opt/homegrown' must not match a bare 'in /home' test."""
    finding = auditor.classify_path("x.service", "/opt/homegrown/x.service")
    assert finding is not None
    assert finding.reason == "non-standard-path"


def test_classify_sibling_of_home_is_not_high_risk():
    finding = auditor.classify_path("x.service", "/home2/x.service")
    assert finding.reason == "non-standard-path"


@pytest.mark.parametrize("path", [
    "/tmp/x.service",
    "/var/tmp/x.service",
    "/dev/shm/x.service",
    "/home/krish/x.service",
])
def test_classify_high_risk_directories(path):
    finding = auditor.classify_path("x.service", path)
    assert finding is not None
    assert finding.reason == "high-risk-path"
    assert finding.severity == auditor.SEVERITY_HIGH


def test_classify_missing_path_is_informational():
    finding = auditor.classify_path("run-abc.scope", None)
    assert finding is not None
    assert finding.reason == "missing-fragment-path"
    assert finding.severity == auditor.SEVERITY_INFO


def test_classify_resolves_symlink_to_standard_dir(tmp_path):
    target = tmp_path / "standard"
    target.mkdir()
    real_unit = target / "cron.service"
    real_unit.write_text("[Unit]\n", encoding="utf-8")
    link = tmp_path / "cron.service"
    link.symlink_to(real_unit)

    # Without resolution the symlink location looks non-standard ...
    unresolved = auditor.classify_path(
        "cron.service", str(link), standard_dirs=(str(target),), resolve_symlinks=False
    )
    assert unresolved is not None
    assert unresolved.reason == "non-standard-path"

    # ... and with resolution it is correctly treated as standard.
    assert auditor.classify_path(
        "cron.service", str(link), standard_dirs=(str(target),), resolve_symlinks=True
    ) is None


def test_classify_custom_standard_dir():
    assert auditor.classify_path(
        "x.service", "/opt/systemd/system/x.service",
        standard_dirs=("/opt/systemd/system",),
    ) is None


# --- audit_services ---------------------------------------------------------

def _show_map(mapping):
    def responder(args):
        return f"FragmentPath={mapping.get(args[1], '')}\n"

    return responder


def test_audit_services_end_to_end(fake):
    fake({
        "list-units": "cron.service loaded active running cron\n"
                      "backdoor.service loaded active running evil\n"
                      "tmpd.service loaded active running evil\n",
        "show": _show_map({
            "cron.service": "/lib/systemd/system/cron.service",
            "backdoor.service": "/opt/payload/backdoor.service",
            "tmpd.service": "/tmp/tmpd.service",
        }),
    })
    report = auditor.audit_services()
    assert report.services_checked == 3
    assert {f.service for f in report.findings} == {"backdoor.service", "tmpd.service"}
    assert report.has_problems is True


def test_audit_services_clean_run(fake):
    fake({
        "list-units": "cron.service loaded active running cron\n",
        "show": _show_map({"cron.service": "/lib/systemd/system/cron.service"}),
    })
    report = auditor.audit_services()
    assert report.findings == []
    assert report.errors == []
    assert report.has_problems is False


def test_audit_services_records_error_and_continues(fake):
    def responder(args):
        if args[1] == "broken.service":
            raise auditor.AuditError("systemctl show broken.service exited 1")
        return "FragmentPath=/tmp/x.service\n"

    fake({
        "list-units": "broken.service loaded active running x\n"
                      "bad.service loaded active running y\n",
        "show": responder,
    })
    report = auditor.audit_services()
    assert report.services_checked == 2
    assert len(report.errors) == 1 and "broken.service" in report.errors[0]
    assert [f.service for f in report.findings] == ["bad.service"]


def test_audit_services_propagates_list_failure(fake):
    fake({"list-units": auditor.AuditError("systemctl not found")})
    with pytest.raises(auditor.AuditError):
        auditor.audit_services()


# --- CLI --------------------------------------------------------------------

def test_main_clean_exit_code(fake, capsys):
    fake({
        "list-units": "cron.service loaded active running cron\n",
        "show": _show_map({"cron.service": "/lib/systemd/system/cron.service"}),
    })
    assert auditor.main([]) == 0
    assert "standard locations" in capsys.readouterr().out


def test_main_findings_exit_code(fake):
    fake({
        "list-units": "bad.service loaded active running x\n",
        "show": _show_map({"bad.service": "/tmp/bad.service"}),
    })
    assert auditor.main([]) == 1


def test_main_unavailable_systemctl_exit_code(fake, capsys):
    fake({"list-units": auditor.AuditError("systemctl not found")})
    assert auditor.main([]) == 2
    assert "systemctl not found" in capsys.readouterr().err


def test_main_json_output_is_parseable(fake, capsys):
    fake({
        "list-units": "bad.service loaded active running x\n",
        "show": _show_map({"bad.service": "/opt/x/bad.service"}),
    })
    assert auditor.main(["--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["services_checked"] == 1
    assert payload["findings"][0]["service"] == "bad.service"
    assert payload["has_problems"] is True


def test_main_honours_custom_standard_path(fake):
    fake({
        "list-units": "x.service loaded active running x\n",
        "show": _show_map({"x.service": "/opt/systemd/system/x.service"}),
    })
    assert auditor.main(["--standard-path", "/opt/systemd/system"]) == 0
