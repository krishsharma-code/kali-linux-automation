#!/usr/bin/env python3
"""Dangling-CNAME subdomain takeover detector.

A subdomain takeover happens when a DNS record (usually a CNAME) still points at
a third-party service whose resource has since been released. Anyone who
re-registers that bucket, page or app can then serve content under the victim's
domain. This tool fetches each candidate host and looks for the provider error
signatures that prove the backing resource is unclaimed.

Safety boundaries
-----------------
* Every host is normalised and validated before it reaches a URL. Anything that
  could retarget the request (``user:pw@host``, a path, a query, a fragment,
  whitespace or a control character) is rejected instead of being pasted into
  an f-string.
* Redirects are **not** followed. The tool only inspects the host it was asked
  about, so a redirect cannot turn it into an SSRF pivot onto an internal
  address. The ``Location`` header is recorded for triage instead.
* The body is streamed and truncated at ``MAX_BODY_BYTES`` so a hostile or
  accidental multi-gigabyte response cannot exhaust memory.

Exit codes (usable as a CI gate):
    0 - no dangling resources found
    1 - at least one potential takeover found
    2 - bad usage or an unreadable host list

Usage:
    python3 subdomain_takeover_check.py dev.example.com blog.example.net
    python3 subdomain_takeover_check.py --hosts-file hosts.txt --json
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urlsplit

import requests

# Error-page fragments that prove the backing resource no longer exists. Keys
# are the provider names used in the report; values are matched case-insensitively
# against the response body because providers are not consistent about casing.
PROVIDER_SIGNATURES = {
    "Amazon S3": "nosuchbucket",
    "GitHub Pages": "there isn't a github pages site here",
    "Heroku": "no such app",
    "Shopify": "sorry, this shop is currently unavailable",
}

# Hosts used when the script is run with no arguments (kept for demo parity
# with the original script; they are documentation examples, not live targets).
DEFAULT_TARGETS = [
    "dev.example-mock.com",
    "bucket-test.s3.amazonaws.com",
    "blog.my-ai-site.io",
]

DEFAULT_SCHEME = "https"
DEFAULT_TIMEOUT = 3.0
DEFAULT_MAX_BYTES = 512 * 1024
DEFAULT_USER_AGENT = (
    "kali-linux-automation/subdomain-takeover-check "
    "(+https://github.com/krishsharma-code/kali-linux-automation)"
)

# A single DNS label: 1-63 chars, alphanumeric at both ends, hyphens inside.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


def normalize_host(value):
    """Return a canonical host string, or ``None`` if ``value`` is unusable.

    Rejects anything that is not a bare host[:port]: credentials, paths, query
    strings, fragments, whitespace, control characters, over-long labels and
    non-string input. This is the input-validation boundary for the whole tool.
    """
    if not isinstance(value, str):
        return None

    host = value.strip().lower().rstrip(".")
    if not host or len(host) > 253:
        return None

    # urlsplit resolves the netloc for us; if it disagrees with the input the
    # input carried a userinfo/path/query/fragment component.
    parts = urlsplit(f"//{host}")
    if parts.netloc != host or not parts.hostname:
        return None
    if parts.username or parts.password:
        # "evil.com@internal.corp" would send the request to internal.corp.
        return None
    if not _HOST_RE.match(parts.hostname):
        return None
    try:
        parts.port  # noqa: B018 - accessing .port raises ValueError on a bad port
    except ValueError:
        return None

    return host


def build_url(host, scheme=DEFAULT_SCHEME):
    """Return the URL to probe for an already-normalised ``host``."""
    return f"{scheme}://{host}"


def fetch_body(url, session=None, timeout=DEFAULT_TIMEOUT,
               max_bytes=DEFAULT_MAX_BYTES, allow_redirects=False):
    """GET ``url`` and return ``(status, headers, body, truncated)``.

    The body is streamed in 8 KiB chunks and cut off at ``max_bytes``, so memory
    use is bounded regardless of what the server sends. ``body`` is the decoded
    prefix with undecodable bytes replaced rather than raising.
    """
    own_session = session is None
    session = session or requests.Session()
    try:
        with session.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            stream=True,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        ) as response:
            chunks = []
            total = 0
            truncated = False
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = max_bytes - total
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)

            body = b"".join(chunks).decode("utf-8", "replace")
            return response.status_code, dict(response.headers), body, truncated
    finally:
        if own_session:
            session.close()


def _match_signature(body):
    """Return the first provider whose error signature appears in ``body``."""
    lowered = body.casefold()
    for provider, signature in PROVIDER_SIGNATURES.items():
        if signature in lowered:
            return provider
    return None


def check_subdomain_takeover(subdomains, session=None, scheme=DEFAULT_SCHEME,
                             timeout=DEFAULT_TIMEOUT, max_bytes=DEFAULT_MAX_BYTES,
                             delay=0.0, stream=sys.stdout):
    """Check ``subdomains`` for dangling-CNAME takeover risk.

    Returns a list of findings::

        {"host": str, "url": str, "provider": str, "status": int,
         "location": str | None, "truncated": bool}

    Invalid hosts are skipped with a message instead of being probed, and a
    failing request is recorded and the loop continues, so one unreachable host
    cannot abort a batch run.
    """
    findings = []
    total = len(subdomains) if hasattr(subdomains, "__len__") else 0
    print(f"[*] Checking {total} subdomains for potential takeover...", file=stream)

    for index, raw in enumerate(subdomains):
        if delay and index:
            time.sleep(delay)

        host = normalize_host(raw)
        if host is None:
            print(f"[-] Skipped invalid host: {raw!r}", file=stream)
            continue

        url = build_url(host, scheme)
        try:
            status, headers, body, truncated = fetch_body(
                url, session=session, timeout=timeout, max_bytes=max_bytes
            )
        except requests.exceptions.RequestException as exc:
            print(f"[?] {host}: connection failed ({type(exc).__name__})", file=stream)
            continue

        provider = _match_signature(body)
        if provider is None:
            print(f"[-] {host}: Secure", file=stream)
            continue

        findings.append({
            "host": host,
            "url": url,
            "provider": provider,
            "status": status,
            "location": headers.get("Location"),
            "truncated": truncated,
        })
        print(f"[!] POTENTIAL TAKEOVER: {host} ({provider})", file=stream)

    return findings


def _read_hosts_file(path):
    """Return the hosts listed in ``path``, or raise ``OSError``."""
    hosts = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if entry and not entry.startswith("#"):
                hosts.append(entry)
    return hosts


def main(argv=None):
    """Parse arguments, run the check and return a process exit code."""
    parser = argparse.ArgumentParser(
        description="Detect dangling-CNAME subdomain takeovers."
    )
    parser.add_argument("hosts", nargs="*", help="hosts to check, e.g. dev.example.com")
    parser.add_argument("--hosts-file", help="file with one host per line ('#' comments)")
    parser.add_argument("--scheme", default=DEFAULT_SCHEME, choices=("http", "https"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"response body cap in bytes (default {DEFAULT_MAX_BYTES})")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds to sleep between requests (default 0)")
    parser.add_argument("--json", action="store_true", help="also print findings as JSON")
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be greater than 0")
    if args.delay < 0:
        parser.error("--delay must not be negative")

    hosts = list(args.hosts)
    if args.hosts_file:
        try:
            hosts.extend(_read_hosts_file(args.hosts_file))
        except OSError as exc:
            print(f"[!] Cannot read host list: {exc}", file=sys.stderr)
            return 2
    if not hosts:
        hosts = list(DEFAULT_TARGETS)

    findings = check_subdomain_takeover(
        hosts,
        scheme=args.scheme,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        delay=args.delay,
    )

    print("-" * 30)
    print(f"[*] Scan complete. Potential takeovers: {len(findings)}")
    if args.json:
        print(json.dumps(findings, indent=2))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
