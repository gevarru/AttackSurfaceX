"""Plugin API.

A plugin is a small Python module exposing:

    META = {"name": ..., "version": ..., "description": ...}
    async def run(ctx) -> list[Finding]

`ctx` is a PluginContext with a rate-limited HTTP client and the scan
configuration. Plugins are sandboxed by policy, not by force: they must
not spawn processes, and the loader refuses modules that import `os`,
`subprocess`, `socket` or `ctypes` directly."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.http import SafeHttpClient


@dataclass
class PluginContext:
    http: "SafeHttpClient"
    base_url: str
    urls: list[str]
    profile: str = "safe"
