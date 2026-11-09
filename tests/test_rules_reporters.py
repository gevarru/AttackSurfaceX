"""Tests for the YAML rules engine and reporters."""
import json

import pytest

from asx.core.models import Confidence, Finding, ScanResult, Severity
from asx.reporters import to_json, to_markdown, to_sarif
from asx.rules.engine import RuleError, evaluate_rules, load_rules


def _rules(tmp_path, body):
    f = tmp_path / "rules.yaml"
    f.write_text(body)
    return str(f)


def test_load_valid_rules(tmp_path):
    path = _rules(tmp_path, """
rules:
  - id: r1
    title: t
    severity: low
    match: {type: header_absent, header: x-test}
    remediation: fix
""")
    rules = load_rules(path)
    assert len(rules) == 1


def test_invalid_severity_rejected(tmp_path):
    path = _rules(tmp_path, """
rules:
  - id: r1
    title: t
    severity: catastrophic
    match: {type: header_absent, header: x-test}
    remediation: fix
""")
    with pytest.raises(RuleError):
        load_rules(path)


def test_invalid_regex_rejected(tmp_path):
    path = _rules(tmp_path, """
rules:
  - id: r1
    title: t
    severity: low
    match: {type: body_regex, pattern: "(["}
    remediation: fix
""")
    with pytest.raises(RuleError):
        load_rules(path)


def test_evaluate_header_absent(tmp_path):
    path = _rules(tmp_path, """
rules:
  - id: r1
    title: missing x-test
    severity: low
    match: {type: header_absent, header: x-test}
    remediation: add the header
""")
    rules = load_rules(path)
    findings = evaluate_rules(rules, "https://t", {"Content-Type": "text/html"}, "")
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert evaluate_rules(rules, "https://t", {"X-Test": "1"}, "") == []


def _sample_result():
    result = ScanResult(target="https://example.com", profile="safe")
    result.add(Finding(
        title="t", severity=Severity.LOW, confidence=Confidence.CERTAIN,
        target="https://example.com", evidence="e", remediation="r", module="m",
    ))
    result.finish()
    return result


def test_json_report_roundtrip():
    text = to_json(_sample_result())
    data = json.loads(text)
    assert data["counts"]["low"] == 1
    assert data["findings"][0]["title"] == "t"


def test_markdown_report_contains_finding():
    md = to_markdown(_sample_result())
    assert "[LOW] t" in md


def test_sarif_structure():
    sarif = json.loads(to_sarif(_sample_result()))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "note"
