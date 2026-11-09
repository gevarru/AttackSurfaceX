"""TLS configuration audit: protocol versions, certificate validity, weak setups.

Read-only handshake probing. No exploitation.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..core.models import Confidence, Finding, Severity


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float = 8.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock
    except (OSError, ssl.SSLError):
        return None


def scan_tls(host: str, port: int = 443) -> list[Finding]:
    findings: list[Finding] = []
    target = f"{host}:{port}"

    # Certificate + negotiated protocol on default context
    ctx = ssl.create_default_context()
    ssock = _handshake(host, port, ctx)
    if ssock is None:
        findings.append(Finding(
            title="TLS handshake failed on default settings",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            target=target,
            evidence="Could not complete a TLS handshake with system-trusted defaults.",
            remediation="Check the TLS listener, certificate chain and SNI configuration.",
            module="tls",
            cwe="CWE-326",
        ))
        return findings

    negotiated = ssock.version()
    cipher = ssock.cipher()
    cert = ssock.getpeercert()
    ssock.close()

    not_after = cert.get("notAfter")
    if not_after:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            sev, msg = Severity.HIGH, "Certificate is EXPIRED"
        elif days < 30:
            sev, msg = Severity.MEDIUM, f"Certificate expires in {days} days"
        else:
            sev, msg = Severity.INFO, f"Certificate valid for {days} more days"
        findings.append(Finding(
            title=f"TLS certificate: {msg}",
            severity=sev,
            confidence=Confidence.CERTAIN,
            target=target,
            evidence=f"notAfter={not_after}; negotiated={negotiated}; cipher={cipher[0] if cipher else 'n/a'}",
            remediation="Renew/replace the certificate; automate renewal (e.g. ACME).",
            module="tls",
            cwe="CWE-295",
        ))

    # Deprecated protocol versions
    for proto, name in [
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ]:
        dep = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        dep.check_hostname = False
        dep.verify_mode = ssl.CERT_NONE
        try:
            dep.minimum_version = proto
            dep.maximum_version = proto
        except (ssl.SSLError, ValueError):
            continue
        if _handshake(host, port, dep) is not None:
            findings.append(Finding(
                title=f"Deprecated protocol accepted: {name}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target=target,
                evidence=f"A handshake restricted to {name} succeeded.",
                remediation=f"Disable {name}; allow only TLS 1.2+ (prefer 1.3).",
                module="tls",
                cwe="CWE-326",
                owasp="A02:2021",
                references=["https://www.rfc-editor.org/rfc/rfc8996"],
            ))

    if not any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        findings.append(Finding(
            title="TLS configuration looks solid",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=target,
            evidence=f"Negotiated {negotiated}; no deprecated protocols accepted; certificate valid.",
            remediation="None.",
            module="tls",
        ))
    return findings
