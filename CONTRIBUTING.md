# Contributing

Thanks for helping make attack-surface scanning safer and more accessible.

## Ground rules

1. **Non-destructive only.** No exploit code, no state-changing requests,
   no credential brute-forcing, no payload execution. Indicators and
   evidence only.
2. **Scope-first.** Every feature must respect the scope enforcement in
   `asx/core/scope.py`. Never add code paths that bypass it.
3. **Privacy in reports.** Evidence must redact secrets (see `_redact` in
   models). Never include full tokens/keys in findings.

## Adding a web module

1. Create `asx/scanners/web/your_module.py` exposing
   `async def scan_xxx(client, ...) -> list[Finding]`.
2. Emit uniform `Finding` objects (severity, confidence, CWE/OWASP,
   evidence, remediation).
3. Wire it into `asx/cli.py::_run_scan` and add tests under `tests/`.

## Adding a plugin (community extensions)

See the bundled example `asx/plugins/bundled/missing_xfo.py`. Plugins are
sandboxed by policy: no system-module imports.

## Code style

- Python 3.11+, type hints where practical.
- `ruff` for lint, `mypy` for types, `pytest` for tests — CI enforces all.
- No new runtime dependency without a strong reason; discuss in an issue first.

## Testing

- Unit tests for parsers/validators.
- Integration tests must run against a local Docker test target only —
  **never against public hosts in CI**.
