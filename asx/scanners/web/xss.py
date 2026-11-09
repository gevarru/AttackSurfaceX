"""Reflected-XSS indicator scan using an inert canary string.

Detects reflection context (HTML / attribute / JS) without executing payloads."""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import httpx

from ...core.models import Confidence, Finding, Severity

CANARY = "asx'\"<xsc9f2>"


def _context(body: str, canary: str) -> str | None:
    idx = body.find(canary)
    if idx == -1:
        return None
    before = body[max(0, idx - 200):idx]
    if re.search(r"<script[^>]*>[^<]*$", before, re.I):
        return "javascript"
    if re.search(r"<[a-zA-Z][^>]*$", before):
        return "tag/attribute"
    return "html"


async def scan_xss(client, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    tested = 0
    for url in [u for u in urls if parse_qsl(urlparse(u).query)][:30]:
        parts = urlparse(url)
        params = parse_qsl(parts.query)
        for key, _ in params:
            if tested >= 60:
                return findings
            probe = urlencode([(k, CANARY if k == key else v) for k, v in params])
            probe_url = urlunparse(parts._replace(query=probe))
            tested += 1
            try:
                resp = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            ctx = _context(resp.text[:300_000], CANARY)
            if ctx:
                findings.append(Finding(
                    title=f"Reflected input without encoding in parameter '{key}' ({ctx} context)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    target=url,
                    evidence=f"Inert canary reflected unencoded in a {ctx} context.",
                    remediation=(
                        "Apply context-appropriate output encoding and validate input. "
                        "Confirm manually with a browser; canary reflection is an indicator, not proof."
                    ),
                    module="web.xss",
                    cwe="CWE-79",
                    owasp="A03:2021",
                    false_positive_notes="Some frameworks encode on render; verify in a real browser.",
                ))
    return findings
