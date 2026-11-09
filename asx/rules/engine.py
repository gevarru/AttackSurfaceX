"""Minimal YAML rules engine: validate + evaluate against a response."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..core.models import Confidence, Finding, Severity

ALLOWED_TYPES = {"header_absent", "header_present", "header_regex", "body_regex"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class RuleError(Exception):
    pass


def load_rules(path: str | Path) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise RuleError(f"{path}: top-level 'rules' list missing")
    for i, rule in enumerate(rules):
        _validate_rule(rule, f"{path}#rule[{i}]")
    return rules


def _validate_rule(rule: dict, where: str) -> None:
    if not isinstance(rule, dict):
        raise RuleError(f"{where}: rule must be a mapping")
    for key in ("id", "title", "severity", "match", "remediation"):
        if key not in rule:
            raise RuleError(f"{where}: missing required key '{key}'")
    if rule["severity"] not in ALLOWED_SEVERITIES:
        raise RuleError(f"{where}: invalid severity '{rule['severity']}'")
    match = rule["match"]
    if not isinstance(match, dict) or match.get("type") not in ALLOWED_TYPES:
        raise RuleError(f"{where}: match.type must be one of {sorted(ALLOWED_TYPES)}")
    if match["type"].startswith("header") and "header" not in match:
        raise RuleError(f"{where}: header-based rule requires 'header'")
    if match["type"].endswith("regex"):
        if "pattern" not in match:
            raise RuleError(f"{where}: regex rule requires 'pattern'")
        try:
            re.compile(match["pattern"])
        except re.error as exc:
            raise RuleError(f"{where}: invalid regex: {exc}") from exc


def evaluate_rules(rules: list[dict], target: str, headers: dict[str, str], body: str) -> list[Finding]:
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for rule in rules:
        match = rule["match"]
        mtype = match["type"]
        hit = False
        evidence = ""
        if mtype == "header_absent":
            hit = match["header"].lower() not in lower_headers
            evidence = f"Header `{match['header']}` absent."
        elif mtype == "header_present":
            hit = match["header"].lower() in lower_headers
            evidence = f"Header `{match['header']}` present."
        elif mtype == "header_regex":
            value = lower_headers.get(match["header"].lower(), "")
            m = re.search(match["pattern"], value)
            hit = bool(m)
            evidence = f"Header `{match['header']}: {value[:80]}` matched /{match['pattern']}/."
        elif mtype == "body_regex":
            m = re.search(match["pattern"], body[:200_000])
            hit = bool(m)
            evidence = "Body matched rule pattern (value redacted)."
        if hit:
            findings.append(Finding(
                title=rule["title"],
                severity=Severity(rule["severity"]),
                confidence=Confidence.CERTAIN,
                target=target,
                evidence=evidence,
                remediation=rule["remediation"],
                module=f"rule:{rule['id']}",
                cwe=rule.get("cwe"),
                owasp=rule.get("owasp"),
            ))
    return findings
