"""Passive subdomain enumeration module."""

from __future__ import annotations

import asyncio
import json
import re

import aiohttp
import dns.resolver

from core.constants import DEFAULT_HEADERS, SubdomainStatus
from core.models import SubdomainResult, ToolkitConfig
from core.rate_limiter import AsyncRateLimiter, ConcurrencyLimiter


def _normalize_subdomain(candidate: str, domain: str) -> str | None:
    value = candidate.strip().lower().replace("*.", "")
    value = value.rstrip(".")
    if not value or " " in value or "@" in value:
        return None
    if value == domain or value.endswith(f".{domain}"):
        return value
    return None


async def _fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    limiter: AsyncRateLimiter,
    key: str,
    delay: float,
) -> str:
    await limiter.wait(key, delay)
    async with session.get(url, headers=DEFAULT_HEADERS) as response:
        if response.status >= 400:
            return ""
        return await response.text()


async def _source_crtsh(
    session: aiohttp.ClientSession, domain: str, limiter: AsyncRateLimiter, delay: float
) -> set[str]:
    raw = await _fetch_text(
        session,
        f"https://crt.sh/?q=%25.{domain}&output=json",
        limiter,
        "crtsh",
        delay,
    )
    results: set[str] = set()
    if not raw:
        return results

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return results

    for row in data:
        name_value = row.get("name_value", "")
        for item in str(name_value).split("\n"):
            if normalized := _normalize_subdomain(item, domain):
                results.add(normalized)
    return results


async def _source_hackertarget(
    session: aiohttp.ClientSession, domain: str, limiter: AsyncRateLimiter
) -> set[str]:
    raw = await _fetch_text(
        session,
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        limiter,
        "hackertarget",
        1.0,
    )
    results: set[str] = set()
    for line in raw.splitlines():
        hostname = line.split(",")[0].strip().lower()
        if normalized := _normalize_subdomain(hostname, domain):
            results.add(normalized)
    return results


async def _source_alienvault(
    session: aiohttp.ClientSession, domain: str, limiter: AsyncRateLimiter
) -> set[str]:
    raw = await _fetch_text(
        session,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        limiter,
        "alienvault",
        1.0,
    )
    results: set[str] = set()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return results

    for row in payload.get("passive_dns", []):
        hostname = row.get("hostname", "")
        if normalized := _normalize_subdomain(str(hostname), domain):
            results.add(normalized)
    return results


async def _source_rapiddns(
    session: aiohttp.ClientSession, domain: str, limiter: AsyncRateLimiter
) -> set[str]:
    raw = await _fetch_text(
        session,
        f"https://rapiddns.io/subdomain/{domain}?full=1",
        limiter,
        "rapiddns",
        1.0,
    )
    pattern = re.compile(rf"([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.{re.escape(domain)})")
    return {
        normalized
        for match in pattern.findall(raw)
        if (normalized := _normalize_subdomain(match, domain)) is not None
    }


async def _source_wayback(
    session: aiohttp.ClientSession, domain: str, limiter: AsyncRateLimiter, delay: float
) -> set[str]:
    raw = await _fetch_text(
        session,
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey",
        limiter,
        "wayback",
        delay,
    )
    results: set[str] = set()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return results

    for row in payload[1:]:
        if not row:
            continue
        url = row[0]
        host = re.sub(r"^https?://", "", str(url)).split("/")[0]
        if normalized := _normalize_subdomain(host, domain):
            results.add(normalized)
    return results


async def _source_securitytrails(
    session: aiohttp.ClientSession,
    domain: str,
    api_key: str,
    limiter: AsyncRateLimiter,
) -> set[str]:
    if not api_key:
        return set()

    await limiter.wait("securitytrails", 1.0)
    headers = {**DEFAULT_HEADERS, "apikey": api_key}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    async with session.get(url, headers=headers) as response:
        if response.status >= 400:
            return set()
        payload = await response.json(content_type=None)

    return {
        f"{item.strip().lower()}.{domain}"
        for item in payload.get("subdomains", [])
        if item and isinstance(item, str)
    }


async def _resolve_ip(hostname: str) -> str | None:
    resolver = dns.resolver.Resolver()

    def _resolve() -> str | None:
        try:
            answers = resolver.resolve(hostname, "A")
            return answers[0].to_text()
        except Exception:
            return None

    return await asyncio.to_thread(_resolve)


async def _classify_subdomain(
    session: aiohttp.ClientSession,
    domain: str,
    limiter: ConcurrencyLimiter,
) -> SubdomainResult:
    url = f"https://{domain}"
    ip = await _resolve_ip(domain)

    status = SubdomainStatus.UNRESOLVABLE if ip is None else SubdomainStatus.LIVE
    redirect_target: str | None = None

    if ip:
        try:
            async with limiter:
                async with session.head(url, allow_redirects=False, timeout=5) as response:
                    if response.status in {301, 302, 307, 308}:
                        status = SubdomainStatus.REDIRECT
                        redirect_target = response.headers.get("Location")
                    elif response.status >= 400:
                        status = SubdomainStatus.UNRESOLVABLE
                    else:
                        status = SubdomainStatus.LIVE
        except Exception:
            pass

    return SubdomainResult(
        name=domain,
        status=status,
        ip=ip,
        source="aggregated",
        redirect_target=redirect_target,
    )


async def detect_wildcard(domain: str) -> bool:
    """Detect wildcard DNS behavior for a target domain."""

    test_name = f"definitely-not-real-{domain}"
    return await _resolve_ip(test_name) is not None


async def enumerate_subdomains(
    domain: str,
    config: ToolkitConfig,
    rate_limiter: AsyncRateLimiter,
) -> tuple[list[SubdomainResult], bool]:
    """Enumerate and classify subdomains from passive sources only."""

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    connector = aiohttp.TCPConnector(limit=config.general.max_concurrent_requests, ssl=False)
    concurrency = ConcurrencyLimiter(config.general.max_concurrent_requests)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        sources = [
            asyncio.create_task(
                _source_crtsh(session, domain, rate_limiter, config.rate_limits.crtsh_delay)
            ),
            asyncio.create_task(_source_hackertarget(session, domain, rate_limiter)),
            asyncio.create_task(_source_alienvault(session, domain, rate_limiter)),
            asyncio.create_task(_source_rapiddns(session, domain, rate_limiter)),
            asyncio.create_task(
                _source_wayback(session, domain, rate_limiter, config.rate_limits.wayback_delay)
            ),
            asyncio.create_task(
                _source_securitytrails(
                    session,
                    domain,
                    config.api_keys.securitytrails,
                    rate_limiter,
                )
            ),
        ]
        source_results = await asyncio.gather(*sources, return_exceptions=True)

        deduped: set[str] = set()
        for result in source_results:
            if isinstance(result, Exception):
                continue
            if isinstance(result, set):
                deduped.update(result)

        classifications = await asyncio.gather(
            *[_classify_subdomain(session, entry, concurrency) for entry in sorted(deduped)]
        )

    wildcard_detected = await detect_wildcard(domain)
    return classifications, wildcard_detected
