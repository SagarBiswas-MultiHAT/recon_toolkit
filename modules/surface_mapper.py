"""Passive attack surface mapper (depth=1 crawl + standard metadata endpoints)."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from core.constants import ADMIN_PATH_CANDIDATES, DEFAULT_HEADERS
from core.models import SurfaceMapData, ToolkitConfig

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def _is_internal(target: str, domain: str) -> bool:
    parsed = urlparse(target)
    if not parsed.netloc:
        return True
    return parsed.netloc == domain or parsed.netloc.endswith(f".{domain}")


def _dedupe(items: list[str]) -> list[str]:
    return sorted(set(item for item in items if item))


def _extract_api_routes(urls: list[str]) -> list[str]:
    indicators = ["/api/", "/v1/", "/graphql", "/rest/"]
    return sorted({url for url in urls if any(token in url.lower() for token in indicators)})


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, headers=DEFAULT_HEADERS) as response:
            if response.status >= 400:
                return ""
            return await response.text(errors="ignore")
    except Exception:
        return ""


async def map_surface(domain: str, config: ToolkitConfig) -> SurfaceMapData:
    """Map passive web surface for root domain with depth-1 extraction."""

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    base_url = f"https://{domain}"

    data = SurfaceMapData()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        html = await _fetch_text(session, base_url)
        soup = BeautifulSoup(html, "lxml")

        all_links: list[str] = []
        for element in soup.find_all("a", href=True):
            all_links.append(urljoin(base_url, str(element["href"])))

        for link in all_links:
            if _is_internal(link, domain):
                data.internal_links.append(link)
            else:
                data.external_links.append(link)

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                data.scripts.append(urljoin(base_url, str(src)))
            elif script.text.strip():
                data.scripts.append("inline-script")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                data.forms.append(urljoin(base_url, str(action)))

        page_text = soup.get_text(" ", strip=True)
        data.emails = _dedupe(EMAIL_PATTERN.findall(page_text + "\n" + html))

        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property")
            content = meta.get("content")
            if name and content:
                data.meta[str(name)] = str(content)

        data.api_routes = _extract_api_routes(data.internal_links + data.forms)

        discovered_admin = {
            path
            for path in ADMIN_PATH_CANDIDATES
            if any(path in entry.lower() for entry in data.internal_links + data.forms)
        }
        data.admin_paths = sorted(discovered_admin)

        robots = await _fetch_text(session, f"{base_url}/robots.txt")
        for line in robots.splitlines():
            if line.lower().startswith("disallow:"):
                _, value = line.split(":", 1)
                data.robots_disallow.append(value.strip())

        sitemap = await _fetch_text(session, f"{base_url}/sitemap.xml")
        if sitemap:
            map_soup = BeautifulSoup(sitemap, "xml")
            data.sitemap_urls = [loc.text.strip() for loc in map_soup.find_all("loc") if loc.text]

        security_txt = await _fetch_text(session, f"{base_url}/.well-known/security.txt")
        for line in security_txt.splitlines():
            if ":" not in line or line.strip().startswith("#"):
                continue
            key, value = line.split(":", 1)
            data.security_txt[key.strip().lower()] = value.strip()

    data.internal_links = _dedupe(data.internal_links)
    data.external_links = _dedupe(data.external_links)
    data.scripts = _dedupe(data.scripts)
    data.forms = _dedupe(data.forms)
    data.robots_disallow = _dedupe(data.robots_disallow)
    data.sitemap_urls = _dedupe(data.sitemap_urls)

    return data
