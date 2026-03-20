"""WHOIS and ASN enrichment module."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import aiohttp
import whois

from core.constants import DEFAULT_HEADERS
from core.models import ToolkitConfig, WhoisAsnData


def _safe_datetime_to_str(value: object) -> str | None:
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


async def _whois_lookup(domain: str) -> dict:
    def _lookup() -> dict:
        result = whois.whois(domain)
        return dict(result) if result else {}

    return await asyncio.to_thread(_lookup)


async def _fetch_json(session: aiohttp.ClientSession, url: str) -> dict:
    async with session.get(url, headers=DEFAULT_HEADERS) as response:
        if response.status >= 400:
            return {}
        return await response.json(content_type=None)


def _is_expiring_soon(expiry_date: str | None, days: int = 90) -> bool:
    if not expiry_date:
        return False
    try:
        expiry = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return (expiry - now).days <= days
    except ValueError:
        return False


async def lookup_whois_asn(domain: str, config: ToolkitConfig, ip_address: str | None) -> WhoisAsnData:
    """Fetch WHOIS, ASN and geolocation context passively."""

    whois_data = await _whois_lookup(domain)

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    data = WhoisAsnData(
        registrar=str(whois_data.get("registrar")) if whois_data.get("registrar") else None,
        creation_date=_safe_datetime_to_str(whois_data.get("creation_date")),
        expiry_date=_safe_datetime_to_str(whois_data.get("expiration_date")),
        registrant_country=str(whois_data.get("country")) if whois_data.get("country") else None,
    )

    if not ip_address:
        data.expiring_soon = _is_expiring_soon(data.expiry_date)
        return data

    async with aiohttp.ClientSession(timeout=timeout) as session:
        ipapi = await _fetch_json(session, f"http://ip-api.com/json/{ip_address}")
        data.asn = str(ipapi.get("as", "")).split(" ")[0] or None
        data.organization = ipapi.get("org")
        data.ip_country = ipapi.get("country")
        data.ip_city = ipapi.get("city")

        reverse_ip_raw = await session.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}",
            headers=DEFAULT_HEADERS,
        )
        if reverse_ip_raw.status < 400:
            text = await reverse_ip_raw.text()
            data.reverse_ip_domains = [line.strip() for line in text.splitlines() if line.strip()]

    data.expiring_soon = _is_expiring_soon(data.expiry_date)
    return data
