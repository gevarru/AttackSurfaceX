"""Shallow, polite crawler: same-host links from a few seed pages."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.I)


async def crawl(client, base_url: str, max_pages: int = 25) -> list[str]:
    base_host = urlparse(base_url).hostname
    seen: set[str] = set()
    queue = [base_url]
    out: list[str] = []
    while queue and len(out) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        out.append(url)
        if "text/html" not in resp.headers.get("content-type", ""):
            continue
        for href in LINK_RE.findall(resp.text[:300_000]):
            abs_url = urljoin(url, href)
            p = urlparse(abs_url)
            if p.hostname == base_host and p.scheme in ("http", "https") and abs_url not in seen:
                queue.append(abs_url)
    return out
