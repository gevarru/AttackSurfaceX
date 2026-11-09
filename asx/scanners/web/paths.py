"""Common exposed-path checks (dotfiles, backups, status pages)."""
from __future__ import annotations

import httpx

from ...core.models import Confidence, Finding, Severity

PATHS = [
    ("/.env", Severity.HIGH, "Environment file may expose secrets."),
    ("/.git/config", Severity.HIGH, "Exposed git repository metadata."),
    ("/.git/HEAD", Severity.MEDIUM, "Exposed git repository metadata."),
    ("/server-status", Severity.MEDIUM, "Apache status page may leak internals."),
    ("/phpinfo.php", Severity.MEDIUM, "phpinfo() discloses configuration details."),
    ("/info.php", Severity.MEDIUM, "phpinfo() discloses configuration details."),
    ("/backup.zip", Severity.HIGH, "Public backup archive may expose source/secrets."),
    ("/backup.tar.gz", Severity.HIGH, "Public backup archive may expose source/secrets."),
    ("/db.sql", Severity.HIGH, "Public database dump may expose data."),
    ("/web.config", Severity.MEDIUM, "IIS configuration file exposed."),
    ("/.DS_Store", Severity.LOW, "macOS metadata file leaks directory listing."),
]


async def scan_paths(client, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    # Baseline: how does the server answer a guaranteed-missing path?
    try:
        probe = await client.get(base + "/asx-404-canary-9f2e7d")
        baseline = probe.status_code
    except httpx.HTTPError:
        return findings

    for path, sev, why in PATHS:
        try:
            resp = await client.get(base + path)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and baseline != 200:
            findings.append(Finding(
                title=f"Exposed sensitive path: {path}",
                severity=sev,
                confidence=Confidence.FIRM,
                target=base + path,
                evidence=f"HTTP 200, {len(resp.content)} bytes. {why}",
                remediation="Remove or deny access to this file at the web-server level; rotate any secrets it may contain.",
                module="web.paths",
                cwe="CWE-200",
                owasp="A05:2021",
            ))
        elif resp.status_code in (401, 403) and path in ("/server-status",):
            findings.append(Finding(
                title=f"Path exists but is protected: {path} ({resp.status_code})",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                target=base + path,
                evidence=f"HTTP {resp.status_code} — access correctly restricted.",
                remediation="None.",
                module="web.paths",
            ))
    return findings
