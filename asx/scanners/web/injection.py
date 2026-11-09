"""Canary-based error/injection indicator checks. Non-destructive only:
we send inert canary strings and look for database/executable error text."""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import httpx

from ...core.models import Confidence, Finding, Severity

CANARY = "asx'\"<cnry9f2>"

ERROR_PATTERNS = [
    (re.compile(r"(?i)(sql syntax|mysql_fetch|ORA-\d{4}|PostgreSQL.*ERROR|sqlite3?\.OperationalError|Unclosed quotation mark)"), "SQL error"),
    (re.compile(r"(?i)(ldap_(error|bind)|Invalid DN syntax)"), "LDAP error"),
    (re.compile(r"(?i)(sh: |bash: |cmd\.exe|/bin/sh:.*not found)"), "shell error"),
]


def _urls_with_params(urls: list[str]) -> list[str]:
    return [u for u in urls if parse_qsl(urlparse(u).query)]


async def scan_injection(client, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for url in _urls_with_params(urls)[:30]:
        parts = urlparse(url)
        params = parse_qsl(parts.query)
        for key, _ in params:
            probe = urlencode([(k, CANARY if k == key else v) for k, v in params])
            probe_url = urlunparse(parts._replace(query=probe))
            if probe_url in seen:
                continue
            seen.add(probe_url)
            try:
                resp = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            for pattern, label in ERROR_PATTERNS:
                m = pattern.search(resp.text[:200_000])
                if m:
                    findings.append(Finding(
                        title=f"Possible injection point ({label}) in parameter '{key}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.TENTATIVE,
                        target=url,
                        evidence=(
                            f"Inert canary triggered a {label} pattern in the response: "
                            f"'{m.group(0)[:60]}' (value redacted)."
                        ),
                        remediation=(
                            "Investigate the code path handling this parameter; use parameterized "
                            "queries / proper escaping. Verify manually before treating as exploitable."
                        ),
                        module="web.injection",
                        cwe="CWE-89" if "SQL" in label else "CWE-77",
                        owasp="A03:2021",
                        false_positive_notes="Error text alone does not prove exploitability.",
                    ))
                    break
    return findings
