"""Web scanners package."""
from .crawler import crawl
from .headers import scan_headers
from .injection import scan_injection
from .paths import scan_paths
from .xss import scan_xss

__all__ = ["crawl", "scan_headers", "scan_injection", "scan_paths", "scan_xss"]
