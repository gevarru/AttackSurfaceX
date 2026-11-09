"""Safe TCP-connect port scanner (asyncio, no raw sockets, no nmap required)."""
from __future__ import annotations

import asyncio

from ..core.models import Confidence, Finding, Severity
from ..core.rate_limit import RateLimiter

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200,
    9300, 11211, 27017,
]

RISKY_SERVICES = {
    21: ("FTP", Severity.MEDIUM, "FTP sends credentials in cleartext. Disable it or require SFTP."),
    23: ("Telnet", Severity.HIGH, "Telnet is cleartext and obsolete. Disable it; use SSH."),
    3306: ("MySQL", Severity.MEDIUM, "Database port exposed. Bind to localhost or restrict by firewall."),
    5432: ("PostgreSQL", Severity.MEDIUM, "Database port exposed. Bind to localhost or restrict by firewall."),
    6379: ("Redis", Severity.HIGH, "Redis exposed. It has no auth by default; bind to localhost and require auth."),
    27017: ("MongoDB", Severity.HIGH, "MongoDB exposed. Restrict network access and enable authentication."),
    9200: ("Elasticsearch", Severity.MEDIUM, "Elasticsearch API exposed. Restrict access and enable security features."),
    11211: ("Memcached", Severity.MEDIUM, "Memcached exposed; usable for DDoS amplification. Bind to localhost."),
    5900: ("VNC", Severity.MEDIUM, "VNC exposed. Restrict by firewall and require strong auth / SSH tunnel."),
}


async def _probe_port(host: str, port: int, timeout: float, rl: RateLimiter) -> tuple[int, str] | None:
    await rl.acquire()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    banner = ""
    try:
        writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=2.0)
        banner = data.decode(errors="replace").strip()[:80]
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return port, banner


async def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    rate: float = 100.0,
    concurrency: int = 100,
) -> list[Finding]:
    """TCP-connect scan of the given host. Non-destructive by design."""
    ports = ports or TOP_PORTS
    rl = RateLimiter(rate=rate, concurrency=concurrency)
    results = await asyncio.gather(*(_probe_port(host, p, timeout, rl) for p in ports))
    open_ports = [r for r in results if r]

    findings: list[Finding] = []
    for port, banner in open_ports:
        if port in RISKY_SERVICES:
            name, sev, fix = RISKY_SERVICES[port]
            findings.append(Finding(
                title=f"Exposed risky service: {name} (port {port})",
                severity=sev,
                confidence=Confidence.CERTAIN,
                target=f"{host}:{port}",
                evidence=f"TCP connect succeeded. Banner: {banner or 'n/a'}",
                remediation=fix,
                module="ports",
                cwe="CWE-284",
                references=["https://owasp.org/www-community/attacks/Port_scanning"],
            ))
        else:
            findings.append(Finding(
                title=f"Open port {port}",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                target=f"{host}:{port}",
                evidence=f"TCP connect succeeded. Banner: {banner or 'n/a'}",
                remediation="Verify this service is intended to be public; otherwise restrict it.",
                module="ports",
            ))
    if not open_ports:
        findings.append(Finding(
            title="No open ports found in scanned set",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=host,
            evidence=f"Scanned {len(ports)} ports, none accepted TCP connections.",
            remediation="None.",
            module="ports",
        ))
    return findings
