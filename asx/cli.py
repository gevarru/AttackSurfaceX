"""AttackSurfaceX CLI (Typer + Rich).

Commands:
  asx scan     full safe scan (headers, TLS, ports, web modules, plugins, rules)
  asx ports    port scan only
  asx plugins  list / info
  asx rules    validate
  asx report   re-render a JSON result as another format
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, reporters
from .core import Finding, ScanResult, Scope, ScopeError, Severity
from .core.http import SafeHttpClient
from .core.rate_limit import RateLimiter
from .plugins import PluginContext, PluginError, load_plugin, load_plugins_dir
from .rules.engine import RuleError, evaluate_rules, load_rules
from .scanners import ports as ports_mod
from .scanners import tls as tls_mod
from .scanners import web

app = typer.Typer(help="AttackSurfaceX — safe, non-destructive attack surface scanner.", no_args_is_help=True)
plugins_app = typer.Typer(help="Manage plugins.", no_args_is_help=True)
rules_app = typer.Typer(help="Manage YAML rules.", no_args_is_help=True)
app.add_typer(plugins_app, name="plugins")
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)

BUNDLED_PLUGINS_DIR = Path(__file__).parent / "plugins" / "bundled"
BUNDLED_RULES = Path(__file__).parent / "rules" / "security_headers.yaml"


def _load_scope(target: str, scope_file: Optional[str]) -> Scope:
    if scope_file:
        scope = Scope.from_file(scope_file)
    else:
        scope = Scope.single(target)
    scope.check_host(target)
    return scope


def _profile_rates(profile: str) -> tuple[float, int]:
    return {"safe": (5.0, 10), "balanced": (20.0, 30), "deep": (50.0, 60)}.get(profile, (5.0, 10))


async def _run_scan(
    target: str,
    scope: Scope,
    profile: str,
    do_ports: bool,
    plugins_dir: Optional[str],
    rules_file: Optional[str],
    result: ScanResult,
) -> None:
    host = scope.check_host(target)
    url = target if "://" in target else f"https://{target}"
    rate, conc = _profile_rates(profile)

    async with SafeHttpClient(RateLimiter(rate, conc)) as http:
        console.print("[cyan]web:[/cyan] security headers & configuration")
        for f in await web.scan_headers(http, url):
            result.add(f)

        console.print("[cyan]web:[/cyan] crawling (shallow)")
        urls = await web.crawl(http, url, max_pages=25 if profile != "deep" else 60)
        result.metadata["crawled_urls"] = len(urls)

        console.print("[cyan]web:[/cyan] exposed paths")
        for f in await web.scan_paths(http, url):
            result.add(f)

        if scope.allow_active_checks and profile in ("balanced", "deep"):
            console.print("[cyan]web:[/cyan] injection indicators (inert canary)")
            for f in await web.scan_injection(http, urls):
                result.add(f)
            console.print("[cyan]web:[/cyan] reflected-XSS indicators (inert canary)")
            for f in await web.scan_xss(http, urls):
                result.add(f)
        else:
            result.metadata["active_checks"] = "skipped (enable with allow_active_checks + balanced/deep profile)"

        rules_path = rules_file or str(BUNDLED_RULES)
        try:
            rules = load_rules(rules_path)
            resp = await http.get(url)
            for f in evaluate_rules(rules, url, dict(resp.headers), resp.text):
                result.add(f)
        except RuleError as exc:
            err_console.print(f"[yellow]rules skipped: {exc}[/yellow]")

        plugin_paths = [BUNDLED_PLUGINS_DIR]
        if plugins_dir:
            plugin_paths.append(Path(plugins_dir))
        ctx = PluginContext(http=http, base_url=url, urls=urls, profile=profile)
        for directory in plugin_paths:
            for plugin in load_plugins_dir(directory):
                try:
                    console.print(f"[cyan]plugin:[/cyan] {plugin.name}")
                    for f in await plugin.run(ctx):
                        result.add(f)
                except Exception as exc:  # plugin failures must not kill the scan
                    err_console.print(f"[yellow]plugin {plugin.name} failed: {exc}[/yellow]")

    console.print("[cyan]tls:[/cyan] certificate & protocol audit")
    for f in await asyncio.to_thread(tls_mod.scan_tls, host, 443):
        result.add(f)

    if do_ports:
        console.print("[cyan]ports:[/cyan] TCP connect scan (top ports)")
        for f in await ports_mod.scan_ports(host, rate=50.0, concurrency=50):
            result.add(f)


def _write_output(result: ScanResult, fmt: str, output: Optional[str]) -> str:
    renders = {
        "json": reporters.to_json,
        "markdown": reporters.to_markdown,
        "html": reporters.to_html,
        "sarif": reporters.to_sarif,
    }
    text = renders[fmt](result)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        console.print(text)
    return text


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="URL or host to scan (must be in scope)."),
    scope_file: Optional[str] = typer.Option(None, "--scope", help="YAML scope file."),
    profile: str = typer.Option("safe", "--profile", "-p", help="safe | balanced | deep"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (default: stdout)."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="json | markdown | html | sarif"),
    ports: bool = typer.Option(True, "--ports/--no-ports", help="Include TCP port scan."),
    plugins_dir: Optional[str] = typer.Option(None, "--plugins-dir", help="Extra plugins directory."),
    rules_file: Optional[str] = typer.Option(None, "--rules", help="Extra YAML rules file."),
) -> None:
    """Run a full safe scan of a target you own or are authorized to test."""
    try:
        scope = _load_scope(target, scope_file)
    except ScopeError as exc:
        err_console.print(f"[red]scope error:[/red] {exc}")
        raise typer.Exit(2)

    result = ScanResult(target=target, profile=profile)
    try:
        asyncio.run(_run_scan(target, scope, profile, ports, plugins_dir, rules_file, result))
    except ScopeError as exc:
        err_console.print(f"[red]scope error:[/red] {exc}")
        raise typer.Exit(2)
    result.finish()

    _write_output(result, fmt, output)
    counts = result.counts()
    console.print(
        f"\n[bold]Done.[/bold] critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )


@app.command()
def ports(
    host: str = typer.Option(..., "--host", help="Host to port-scan (must be in scope)."),
    scope_file: Optional[str] = typer.Option(None, "--scope", help="YAML scope file."),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of common ports (max bounded by scope)."),
    rate: float = typer.Option(100.0, "--rate", help="Max connections per second."),
    fmt: str = typer.Option("json", "--format", "-f", help="json | markdown"),
) -> None:
    """Scan TCP ports on a single host (asyncio connect scan, non-destructive)."""
    try:
        scope = _load_scope(host, scope_file)
        scope.check_port_count(top_ports)
    except ScopeError as exc:
        err_console.print(f"[red]scope error:[/red] {exc}")
        raise typer.Exit(2)
    selected = ports_mod.TOP_PORTS[:top_ports]
    findings = asyncio.run(ports_mod.scan_ports(host, ports=selected, rate=rate, concurrency=int(rate)))
    result = ScanResult(target=host, profile="ports", findings=findings)
    result.finish()
    _write_output(result, "markdown" if fmt == "markdown" else "json", None)


@plugins_app.command("list")
def plugins_list(
    plugins_dir: Optional[str] = typer.Option(None, "--plugins-dir"),
) -> None:
    """List bundled and extra plugins."""
    table = Table(title="AttackSurfaceX plugins")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Description")
    table.add_column("Source")
    for directory, label in [(BUNDLED_PLUGINS_DIR, "bundled"), (Path(plugins_dir), "extra") if plugins_dir else None]:
        if directory is None:
            continue
        for p in load_plugins_dir(directory):
            table.add_row(p.name, p.version, p.description, label)
    console.print(table)


@plugins_app.command("info")
def plugins_info(
    name: str = typer.Argument(..., help="Plugin name or path."),
    plugins_dir: Optional[str] = typer.Option(None, "--plugins-dir"),
) -> None:
    """Show details of one plugin."""
    candidates = list(BUNDLED_PLUGINS_DIR.glob("*.py"))
    if plugins_dir:
        candidates += list(Path(plugins_dir).glob("*.py"))
    for file in candidates:
        try:
            p = load_plugin(file)
        except PluginError:
            continue
        if p.name == name or file.stem == name:
            console.print(f"[bold]{p.name}[/bold] v{p.version}\n{p.description}\npath: {p.path}")
            return
    err_console.print(f"[red]plugin not found:[/red] {name}")
    raise typer.Exit(1)


@rules_app.command("validate")
def rules_validate(
    rules_file: Optional[str] = typer.Option(None, "--rules", help="Rules file (default: bundled)."),
) -> None:
    """Validate a YAML rules file."""
    path = rules_file or str(BUNDLED_RULES)
    try:
        rules = load_rules(path)
    except RuleError as exc:
        err_console.print(f"[red]invalid:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"[green]OK[/green] — {len(rules)} valid rules in {path}")


@app.command()
def report(
    input_file: str = typer.Option(..., "--input", "-i", help="JSON result file from a previous scan."),
    fmt: str = typer.Option("html", "--format", "-f", help="json | markdown | html | sarif"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Re-render a stored JSON result into another format."""
    data = json.loads(Path(input_file).read_text(encoding="utf-8"))
    result = ScanResult(target=data["target"], profile=data.get("profile", "unknown"))
    result.metadata = data.get("metadata", {})
    result.started_at = data.get("started_at", result.started_at)
    result.finished_at = data.get("finished_at")
    from .core.models import Confidence
    for fd in data.get("findings", []):
        result.add(Finding(
            title=fd["title"], severity=Severity(fd["severity"]),
            confidence=Confidence(fd["confidence"]), target=fd["target"],
            evidence=fd["evidence"], remediation=fd["remediation"],
            module=fd["module"], cwe=fd.get("cwe"), owasp=fd.get("owasp"),
            references=fd.get("references", []),
            false_positive_notes=fd.get("false_positive_notes", ""),
        ))
    _write_output(result, fmt, output)


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"AttackSurfaceX {__version__}")


if __name__ == "__main__":
    app()
