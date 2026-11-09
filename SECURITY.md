# Security Policy

## Scope of this project

AttackSurfaceX is a **defensive, non-destructive** scanner. It is designed to
never exploit vulnerabilities, never change target state, and never send
anything but read-only requests (plus inert canary strings in active-check
mode).

## Reporting a vulnerability in AttackSurfaceX itself

If you find a security issue in this tool (e.g. the plugin sandbox being
bypassable, secrets leaking into reports, SSRF in the crawler):

- Open a **private** GitHub Security Advisory on this repository, or
- Email the maintainer (see GitHub profile).

Please do not open public issues for exploitable problems. We aim to
acknowledge within 72 hours.

## Reporting false positives

Public issues are welcome for false positives — the `false_positive_notes`
field exists precisely because indicator-based detection can over-report.

## Legal notice

Only scan systems you own or are explicitly authorized to test. Unauthorized
scanning may be illegal in your jurisdiction (e.g. computer-misuse laws).
You are solely responsible for how you use this software.
