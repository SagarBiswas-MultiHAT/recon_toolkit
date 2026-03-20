"""Wayback Machine integration for historical passive URL analysis."""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

import aiohttp

from core.constants import DEFAULT_HEADERS, WAYBACK_HIGH_RISK_KEYWORDS
from core.models import ToolkitConfig, WaybackData
from core.rate_limiter import AsyncRateLimiter

logger = logging.getLogger("recon_toolkit")


async def fetch_wayback_urls(
    domain: str,
    config: ToolkitConfig,
    rate_limiter: AsyncRateLimiter,
    max_results: int = 100,
) -> WaybackData:
    """Fetch and classify historical URLs from archive.org CDX API."""

    await rate_limiter.wait("wayback", config.rate_limits.wayback_delay)

    query = (
        "https://web.archive.org/cdx/search/cdx?"
        f"url=*.{domain}&output=json&fl=original&collapse=urlkey"
    )
    timeout = aiohttp.ClientTimeout(total=20)

    for attempt in range(2):
        try:
            result = WaybackData()

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(query, headers=DEFAULT_HEADERS) as response:
                    if response.status >= 400:
                        return result
                    body = await response.text()

            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return result

            urls = [row[0] for row in payload[1:] if row and isinstance(row[0], str)]
            deduped = sorted(set(urls))[:max_results]
            result.urls = deduped

            subdomains: set[str] = set()
            for url in deduped:
                host = urlparse(url).netloc.lower()
                if host.endswith(domain) and host != domain:
                    subdomains.add(host)

                lowered = url.lower()
                if any(keyword in lowered for keyword in WAYBACK_HIGH_RISK_KEYWORDS):
                    result.risky_urls.append(url)

            result.historical_subdomains = sorted(subdomains)
            result.risky_urls = sorted(set(result.risky_urls))
            return result
        except TimeoutError:
            if attempt < 1:
                await asyncio.sleep(3)
                continue
            logger.warning("Wayback archive unavailable (timeout) — skipping.")
            return WaybackData()
        except Exception as e:
            logger.error(f"wayback failed: {e!r}")
            return WaybackData()

    return WaybackData()
