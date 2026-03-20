"""Passive technology detection via headers, HTML and static indicators."""

from __future__ import annotations

import re
from urllib.parse import urljoin

import aiohttp
import mmh3
from bs4 import BeautifulSoup

from core.constants import DEFAULT_HEADERS
from core.models import TechStackData, ToolkitConfig

COOKIE_FINGERPRINTS = {
    "phpsessid": ("runtime", "PHP"),
    "asp.net_sessionid": ("runtime", "ASP.NET"),
    "jsessionid": ("runtime", "Java"),
}

SCRIPT_HINTS = {
    "wp-content": ("cms", "WordPress"),
    "/sites/default": ("cms", "Drupal"),
    "react": ("frontend", "React"),
    "vue": ("frontend", "Vue"),
    "angular": ("frontend", "Angular"),
    "jquery": ("frontend", "jQuery"),
}

ANALYTICS_HINTS = {
    "googletagmanager": "Google Analytics",
    "google-analytics": "Google Analytics",
    "hotjar": "Hotjar",
    "mixpanel": "Mixpanel",
}


def _insert_unique(target: list[str], value: str) -> None:
    """Append value to target only if not already present (case-insensitive)."""
    if not value:
        return
    lowered_existing = {item.lower() for item in target}
    if value.lower() not in lowered_existing:
        target.append(value)


def _detect_from_headers(headers: dict[str, str], data: TechStackData) -> None:
    """Extract technology indicators from HTTP response headers."""
    header_lower = {k.lower(): v for k, v in headers.items()}

    server = headers.get("server") or headers.get("Server") or header_lower.get("server", "")
    powered = header_lower.get("x-powered-by", "")

    if server:
        _insert_unique(data.web_server, server)
        _insert_unique(data.evidence, f"server:{server}")

    if powered:
        _insert_unique(data.evidence, f"x-powered-by:{powered}")

    for token, label in [
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("iis", "IIS"),
        ("caddy", "Caddy"),
    ]:
        if token in server.lower():
            _insert_unique(data.web_server, label)

    runtime_checks = {
        "php": "PHP",
        "express": "Node.js/Express",
        "python": "Python",
        "asp.net": "ASP.NET",
        "java": "Java",
    }

    for token, label in runtime_checks.items():
        if token in powered.lower() or token in server.lower():
            _insert_unique(data.runtime, label)

    # Cloudflare detection via cf-ray header
    cf_ray = header_lower.get("cf-ray")
    if cf_ray:
        _insert_unique(data.cdn_waf, "Cloudflare")

    # Akamai detection
    if header_lower.get("x-akamai-transformed") or "akamai" in server.lower():
        _insert_unique(data.cdn_waf, "Akamai")

    # Fastly detection
    if header_lower.get("x-served-by", "").startswith("cache-"):
        _insert_unique(data.cdn_waf, "Fastly")

    # AWS CloudFront detection
    if "cloudfront" in header_lower.get("via", "").lower():
        _insert_unique(data.cdn_waf, "AWS CloudFront")


def _detect_from_html(html: str, base_url: str, data: TechStackData) -> None:
    """Extract technology indicators from HTML content."""
    soup = BeautifulSoup(html, "lxml")

    # Generator meta tag
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        content = str(generator.get("content"))
        _insert_unique(data.evidence, f"generator:{content}")
        if "wordpress" in content.lower():
            _insert_unique(data.cms, "WordPress")
        if "drupal" in content.lower():
            _insert_unique(data.cms, "Drupal")
        if "joomla" in content.lower():
            _insert_unique(data.cms, "Joomla")
        if "shopify" in content.lower():
            _insert_unique(data.cms, "Shopify")

    # Framework hints in HTML body
    html_lower = html.lower()
    if "laravel" in html_lower:
        _insert_unique(data.frameworks, "Laravel")
    if "django" in html_lower:
        _insert_unique(data.frameworks, "Django")
    if "rails" in html_lower:
        _insert_unique(data.frameworks, "Rails")
    if "spring" in html_lower:
        _insert_unique(data.frameworks, "Spring")

    # Script and link src analysis
    for script in soup.find_all(["script", "link"]):
        src = script.get("src") or script.get("href")
        if not src:
            continue
        full_src = urljoin(base_url, str(src))
        low = full_src.lower()

        for token, (kind, label) in SCRIPT_HINTS.items():
            if token in low:
                existing = getattr(data, kind)
                if label not in existing:
                    existing.append(label)

        for token, label in ANALYTICS_HINTS.items():
            if token in low:
                _insert_unique(data.analytics, label)

    # HTML comment hints
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    for comment in comments:
        if "wordpress" in comment.lower():
            _insert_unique(data.cms, "WordPress")


def _detect_from_cookies(cookies: list[str], data: TechStackData) -> None:
    """Extract technology indicators from cookie names."""
    for cookie in cookies:
        low = cookie.lower()
        for token, (kind, label) in COOKIE_FINGERPRINTS.items():
            if token in low:
                _insert_unique(getattr(data, kind), label)
                _insert_unique(data.evidence, f"cookie:{cookie}")


def _favicon_hash(content: bytes) -> int:
    """Compute MurmurHash3 of favicon bytes for fingerprinting."""
    return mmh3.hash(content)


async def detect_tech_stack(domain: str, config: ToolkitConfig) -> TechStackData:
    """Detect probable technologies from passive HTTP responses."""

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    data = TechStackData()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(
            f"https://{domain}", headers=DEFAULT_HEADERS
        ) as response:
            html = await response.text(errors="ignore")
            headers = dict(response.headers)
            cookies = list(response.cookies.keys())
            _detect_from_headers(headers, data)
            _detect_from_html(html, f"https://{domain}", data)
            _detect_from_cookies(cookies, data)

        try:
            async with session.get(
                f"https://{domain}/favicon.ico", headers=DEFAULT_HEADERS
            ) as fav_resp:
                if fav_resp.status < 400:
                    favicon = await fav_resp.read()
                    data.evidence.append(f"favicon_mmh3:{_favicon_hash(favicon)}")
        except Exception:
            pass

    # Deduplicate and sort each technology category
    for key in ["web_server", "runtime", "frameworks", "cms", "cdn_waf", "frontend", "analytics"]:
        setattr(data, key, sorted(set(getattr(data, key))))

    # Cross-field dedup: remove web_server entries already captured in cdn_waf
    # e.g. raw "cloudflare" from Server header vs "Cloudflare" from cf-ray header
    cdn_waf_lower = {v.lower() for v in data.cdn_waf}
    data.web_server = [v for v in data.web_server if v.lower() not in cdn_waf_lower]

    return data
