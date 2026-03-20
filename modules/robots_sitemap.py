"""Passive robots.txt and sitemap.xml parser module."""

from __future__ import annotations

import aiohttp
from bs4 import BeautifulSoup

from core.constants import DEFAULT_HEADERS
from core.models import ToolkitConfig


async def parse_robots_sitemap(domain: str, config: ToolkitConfig) -> dict[str, list[str]]:
    """Parse robots.txt and sitemap.xml and return discovered paths/URLs."""

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    base = f"https://{domain}"
    output = {"robots_disallow": [], "sitemap_urls": []}

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(f"{base}/robots.txt", headers=DEFAULT_HEADERS) as response:
                if response.status < 400:
                    text = await response.text(errors="ignore")
                    for line in text.splitlines():
                        if line.lower().startswith("disallow:"):
                            _, value = line.split(":", 1)
                            output["robots_disallow"].append(value.strip())
        except Exception:
            pass

        try:
            async with session.get(f"{base}/sitemap.xml", headers=DEFAULT_HEADERS) as response:
                if response.status < 400:
                    xml = await response.text(errors="ignore")
                    soup = BeautifulSoup(xml, "xml")
                    output["sitemap_urls"] = [loc.text.strip() for loc in soup.find_all("loc") if loc.text]
        except Exception:
            pass

    output["robots_disallow"] = sorted(set(output["robots_disallow"]))
    output["sitemap_urls"] = sorted(set(output["sitemap_urls"]))
    return output
