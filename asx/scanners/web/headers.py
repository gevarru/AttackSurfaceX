"""Security headers, cookies, CORS and version-disclosure audit."""
from __future__ import annotations

import re

import httpx

from ...core.models import Confidence, Finding, Severity

HEADERS = [
    ("strict-transport-security", "Missing HSTS header", Severity.LOW,
     "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.", "CWE-319"),
    ("content-security-policy", "Missing Content-Security-Policy", Severity.LOW,
     "Start with a Report-Only policy, e.g. `default-src 'self'`, then enforce.", "CWE-1021"),
    ("x-frame-options", "Missing X-Frame-Options (clickjacking)", Severity.LOW,
     "Set `X-Frame-Options: DENY` or `SAMEORIGIN` (or a CSP frame-ancestors).", "CWE-1021"),
    ("x-content-type-options", "Missing X-Content-Type-Options", Severity.INFO,
     "Set `X-Content-Type-Options: nosniff`.", "CWE-693"),
    ("referrer-policy", "Missing Referrer-Policy", Severity.INFO,
     "Set `Referrer-Policy: strict-origin-when-cross-origin`.", "CWE-200"),
    ("permissions-policy", "Missing Permissions-Policy", Severity.INFO,
     "Add a restrictive `Permissions-Policy` header.", "CWE-693"),
]

VERSION_RE = re.compile(r"([A-Za-z][\w-]*)/([0-9][0-9A-Za-z.\-]*)")
SENSITIVE_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key material"),
    (re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*[\"']?[\w\-/+=]{16,}"), "possible hardcoded credential"),
]


async def scan_headers(client, url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return [Finding(
            title="Target unreachable over HTTP(S)",
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            target=url,
            evidence=str(exc),
            remediation="Verify the URL and that the service is up.",
            module="web.headers",
        )]

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    for name, title, sev, fix, cwe in HEADERS:
        if name not in hdrs:
            findings.append(Finding(
                title=title, severity=sev, confidence=Confidence.CERTAIN, target=url,
                evidence=f"Header `{name}` absent in response (status {resp.status_code}).",
                remediation=fix, module="web.headers", cwe=cwe,
                owasp="A05:2021",
            ))

    server = hdrs.get("server", "")
    xpb = hdrs.get("x-powered-by", "")
    for header_name, value in (("Server", server), ("X-Powered-By", xpb)):
        m = VERSION_RE.search(value)
        if m:
            findings.append(Finding(
                title=f"Version disclosure via {header_name} header",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                target=url,
                evidence=f"{header_name}: {value}",
                remediation="Hide detailed version banners (e.g. `ServerTokens Prod`, remove X-Powered-By).",
                module="web.headers", cwe="CWE-200", owasp="A05:2021",
            ))

    for cookie in resp.cookies.jar:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure")
        rest = cookie._rest if hasattr(cookie, "_rest") else {}
        if not any(k.lower() == "httponly" for k in rest):
            issues.append("missing HttpOnly")
        if issues:
            findings.append(Finding(
                title=f"Cookie '{cookie.name}' flags: {', '.join(issues)}",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                target=url,
                evidence=f"Set-Cookie for '{cookie.name}' lacks: {', '.join(issues)}.",
                remediation="Set Secure, HttpOnly and SameSite on all session cookies.",
                module="web.headers", cwe="CWE-614", owasp="A05:2021",
                false_positive_notes="CSRF-token cookies may legitimately need JS access.",
            ))

    acao = hdrs.get("access-control-allow-origin")
    if acao == "*":
        findings.append(Finding(
            title="Permissive CORS: Access-Control-Allow-Origin: *",
            severity=Severity.LOW,
            confidence=Confidence.CERTAIN,
            target=url,
            evidence="Wildcard origin on the main page response.",
            remediation="Restrict allowed origins to explicit trusted domains.",
            module="web.headers", cwe="CWE-942", owasp="A05:2021",
        ))

    body = resp.text[:200_000]
    for pattern, label in SENSITIVE_PATTERNS:
        m = pattern.search(body)
        if m:
            findings.append(Finding(
                title=f"Possible sensitive data exposure: {label}",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                target=url,
                evidence="Pattern matched in response body (value redacted).",
                remediation="Remove the secret from the response, rotate it, and audit access logs.",
                module="web.headers", cwe="CWE-200", owasp="A02:2021",
                false_positive_notes="Verify manually; pattern-based detection can over-match.",
            ))
    return findings
