---
title: "I built a non-destructive attack surface scanner in Python — here's what real targets taught me"
published: false
description: "AttackSurfaceX is a safe, scope-enforced attack surface scanner. This is an honest post about what running it against real, hardened targets actually looks like."
tags: python, security, opensource, devsecops, cli
---

# I built a non-destructive attack surface scanner in Python — here's what real targets taught me

**AttackSurfaceX (ASX)** is an open-source, CLI-first attack surface scanner with one hard design rule: *it must never be able to hurt the target*. No exploits, no fuzzing payloads, no write operations — detection only, behind a strict scope gate.

```bash
pipx install git+https://github.com/gevarru/AttackSurfaceX.git
asx scan -t https://example.com -p safe
```

![demo](docs/asx_demo.gif)

## Why "non-destructive" is the whole point

Most recon tools assume you trust yourself. ASX assumes you'll run it against production systems at 2 AM. That drove three architectural decisions:

**1. Scope enforcement before anything else.** Nothing is scanned unless it's declared in `scope.yaml`. Wide scans require an explicit flag. The scanner refuses to even resolve a host outside the declared scope.

**2. A plugin safety gate.** Plugins are third-party Python, so the loader statically inspects imports — a plugin that touches `os`, `subprocess`, or raw `socket` is refused before it ever runs.

**3. GET/HEAD only.** The HTTP layer physically cannot send state-changing requests. Rate-limited, self-identifying User-Agent, fixed timeouts.

Modules: asyncio TCP port scan with banner grabbing, a TLS audit (cert chain, deprecated protocol detection — read-only handshakes), web checks (security headers, cookie flags, CORS, version disclosure, exposed sensitive paths, inert reflected-XSS canaries), a YAML rules engine, and reporters for **JSON / Markdown / interactive HTML / SARIF** (GitHub Code Scanning). MIT licensed, Python 3.11+.

## What real targets actually taught me

I want this part to be honest, because most "I built a scanner" posts only show the happy path. Here's what happened when ASX met real, hardened perimeters.

**Lesson 1: Geo-blocking is indistinguishable from TLS failure — and your scanner will lie about it.**
The first real run was against a major fintech. Every port "closed", TLS handshake "failed", HTTP "unreachable". It looked like a finding (CWE-326, medium). In reality, the target silently drops connections from certain countries at the CDN edge. The packets never arrived. The scanner wasn't measuring the target's security — it was measuring my network position.

*Fix in progress:* a dedicated `target-unreachable/filtered` finding type, triggered when TCP fails across the entire port set and TLS never completes. If your scanner can't tell "firewalled" from "broken crypto", it will file false reports — and in a bug bounty context, false reports are reputation damage.

**Lesson 2: Modern SPAs return HTTP 200 for everything.**
Exposed-path scanning (`/.git/HEAD`, `/.env`, `/swagger.json`) hits a wall: single-page apps serve the index HTML with a 200 for *any* path. Naive checking produced dozens of "exposed .git" hits that were all the same 12 KB of HTML. The discriminator is **content variance** — real endpoints differ in size and type from the catch-all shell. The same host that shows 200 for `/backup.zip` will 401 or 404 for the real thing once you follow the variance.

**Lesson 3: The clean exit is a feature.**
While recording the demo GIF, asciinema exposed a bug the unit tests missed: after writing the report, the CLI **hangs** instead of exiting. Root cause: unclosed resources (async client / pending tasks) keeping the event loop alive. The scan was fine; the process wasn't. If you pipe this into CI or a shell script, a scanner that won't exit *is* a bug. Fixed by treating "process exits 0 promptly" as a first-class acceptance test.

## The verdict after the first recon runs

Against top-tier perimeters (large fintech, food delivery platform), ASX found **zero reportable vulnerabilities from the outside**. That is the correct result — mature programs are externally clean. The scanner's value isn't finding magic bugs in port 443; it's mapping the surface cheaply and *safely* so human effort can go where bugs actually live: authenticated application logic.

## Roadmap

- CSRF & form-analysis module
- Session/authenticated scanning helpers
- SBOM / supply-chain scanning (OSV integration)
- Resume support for long scans
- `target-unreachable` classification (Lesson 1)

## Try it

```bash
git clone https://github.com/gevarru/AttackSurfaceX.git
cd AttackSurfaceX
pip install -e .
python -m asx.cli scan -t https://your-own-domain.com -p safe
```

Only scan what you own or are authorized to test. ASX detects indicators — it never exploits them.

⭐ [github.com/gevarru/AttackSurfaceX](https://github.com/gevarru/AttackSurfaceX)
