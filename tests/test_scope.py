"""Tests for scope validation and enforcement."""
import pytest

from asx.core.scope import Scope, ScopeError, extract_host, is_private_host


def test_extract_host_from_url():
    assert extract_host("https://Example.com/path?q=1") == "example.com"


def test_extract_host_bare():
    assert extract_host("example.com") == "example.com"
    assert extract_host("example.com:8443") == "example.com"


def test_extract_host_invalid():
    with pytest.raises(ScopeError):
        extract_host("")


def test_scope_allows_declared_host():
    scope = Scope(hosts=["example.com"])
    assert scope.check_host("https://example.com/x") == "example.com"


def test_scope_blocks_foreign_host():
    scope = Scope(hosts=["example.com"])
    with pytest.raises(ScopeError):
        scope.check_host("https://evil.example.org")


def test_wide_port_scan_requires_flag():
    scope = Scope(hosts=["example.com"], max_ports=100)
    with pytest.raises(ScopeError):
        scope.check_port_count(1000)
    scope.allow_wide_port_scan = True
    scope.check_port_count(1000)  # no error


def test_localhost_is_private():
    assert is_private_host("localhost") is True


def test_scope_from_file(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("hosts: [example.com]\nallow_active_checks: true\n")
    scope = Scope.from_file(str(f))
    assert scope.hosts == ["example.com"]
    assert scope.allow_active_checks is True
    assert scope.allow_wide_port_scan is False
