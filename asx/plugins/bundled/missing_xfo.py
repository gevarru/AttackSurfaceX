"""Bundled example plugin: flags a missing X-Frame-Options header.

Educational template for community plugins — passive, read-only."""
from __future__ import annotations

META = {
    "name": "missing-xfo",
    "version": "1.0.0",
    "description": "Flags responses missing the X-Frame-Options header (clickjacking indicator).",
}

from asx.core.models import Confidence, Finding, Severity


async def run(ctx):
    resp = await ctx.http.get(ctx.base_url)
    if "x-frame-options" not in {k.lower() for k in resp.headers}:
        return [Finding(
            title="Missing X-Frame-Options header (plugin)",
            severity=Severity.LOW,
            confidence=Confidence.CERTAIN,
            target=ctx.base_url,
            evidence="Response headers do not include X-Frame-Options.",
            remediation="Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or CSP frame-ancestors.",
            module="plugin:missing-xfo",
            cwe="CWE-1021",
            owasp="A05:2021",
        )]
    return []
