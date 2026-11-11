---
name: asx-security-scan
description: Run AttackSurfaceX (ASX), a safe non-destructive attack surface scanner, against authorized targets. Use when the user asks to scan or audit a domain they own or are permitted to test, check security headers/TLS/exposed paths, or map an attack surface without exploiting anything.
---

# ASX Security Scan

[AttackSurfaceX (ASX)](https://github.com/gevarru/AttackSurfaceX) is an open-source (MIT),
non-destructive attack surface scanner. It detects indicators only and can never send
state-changing requests: asyncio TCP port scan with banner grabbing, TLS audit (cert
chain, deprecated protocols — read-only handshakes), web checks (security headers,
cookie flags, CORS, version disclosure, exposed sensitive paths), a YAML rules engine,
and reports in JSON / Markdown / interactive HTML / SARIF.

## When to use

- "Scan / audit / check example.com" — only for targets the user **owns** or has
  **written authorization** to test.
- Hardening reviews: missing HSTS / X-Frame-Options / Permissions-Policy, TLS
  configuration, exposed `.git` / `.env` style paths.
- Safe external recon before deeper, manual testing.

## Do NOT use

- Any target without explicit authorization. No permission = no scan.
- Exploitation, fuzzing, credential attacks, brute force. ASX cannot do these —
  do not try to make it.
- Raising scan rates. Defaults are deliberately rate-limited; keep them.

## Setup

```bash
pipx install git+https://github.com/gevarru/AttackSurfaceX.git
asx --help   # verify install
```

## Usage

Always start with the `safe` profile:

```bash
asx scan -t https://example.com -p safe -f markdown -o report.md
asx scan -t https://example.com -p safe -f json    -o report.json
```

HTML (`-f html`) gives an interactive report; SARIF (`-f sarif`) imports into
GitHub Code Scanning.

## Interpreting results

- **critical/high** — rare from the outside on mature targets; verify carefully
  before claiming impact.
- **low** — usually hardening gaps (e.g. missing `Strict-Transport-Security`,
  `X-Frame-Options`). Give the exact header and value to add.
- **info** — context: open ports, TLS validity window, missing `Permissions-Policy`.
- ASX deduplicates overlapping findings (built-in modules vs plugins);
  `duplicates_suppressed` in JSON output counts merged items.
- If *every* port looks closed and TLS always fails, the target may be geo-filtering
  you — say so instead of reporting a TLS weakness.

## Safety rules (never skip)

1. Confirm authorization/scope before running anything.
2. Prefer `safe`; suggest `balanced`/`deep` only for owned assets.
3. Explain CWE / OWASP references in plain language.
4. Report findings honestly — a false positive damages trust more than a slow scan.
