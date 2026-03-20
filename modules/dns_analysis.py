"""Passive DNS records and misconfiguration analysis."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.query
import dns.resolver
import dns.zone

from core.models import DnsRecordSet, Finding

CDN_RANGES = {
    "Cloudflare": ["104.16.0.0/13", "172.64.0.0/13"],
    "Fastly": ["151.101.0.0/16"],
    "Akamai": ["23.0.0.0/8"],
    "CloudFront": ["13.32.0.0/15", "52.46.0.0/18"],
}

TAKEOVER_FINGERPRINTS = {
    "github.io": "Potential unclaimed GitHub Pages CNAME",
    "herokudns.com": "Potential unclaimed Heroku app CNAME",
    "fastly.net": "Potential dangling Fastly service",
    "azurewebsites.net": "Potential dangling Azure App Service",
}


def _in_cdn_range(ip_value: str) -> str | None:
    ip_obj = ipaddress.ip_address(ip_value)
    for provider, ranges in CDN_RANGES.items():
        for cidr in ranges:
            if ip_obj in ipaddress.ip_network(cidr):
                return provider
    return None


async def _resolve_record(domain: str, record_type: str) -> list[str]:
    resolver = dns.resolver.Resolver()

    def _query() -> list[str]:
        try:
            return [answer.to_text().strip() for answer in resolver.resolve(domain, record_type)]
        except Exception:
            return []

    return await asyncio.to_thread(_query)


async def _attempt_axfr(domain: str, nameservers: list[str]) -> bool:
    def _axfr() -> bool:
        for ns in nameservers:
            host = ns.rstrip(".")
            try:
                transfer = dns.query.xfr(host, domain, lifetime=3)
                zone = dns.zone.from_xfr(transfer)
                if zone and len(zone.nodes) > 0:
                    return True
            except Exception:
                continue
        return False

    return await asyncio.to_thread(_axfr)


def _spf_valid(txt_records: list[str]) -> bool:
    return any(record.startswith('"v=spf1') or record.startswith("v=spf1") for record in txt_records)


def _dmarc_valid(txt_records: list[str]) -> bool:
    return any("v=DMARC1" in record for record in txt_records)


def _detect_takeover(cnames: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for cname in cnames:
        for fingerprint, message in TAKEOVER_FINGERPRINTS.items():
            if fingerprint in cname.lower():
                findings.append(
                    Finding(
                        id="DNS-TAKEOVER-001",
                        category="DNS",
                        finding=f"{message}: {cname}",
                        risk="HIGH",
                        score_impact=7,
                        recommendation="Validate ownership and remove dangling DNS records.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    )
                )
    return findings


async def analyze_dns(domain: str) -> DnsRecordSet:
    """Collect DNS records and derive passive DNS risk indicators."""

    records = DnsRecordSet()
    records.a = await _resolve_record(domain, "A")
    records.aaaa = await _resolve_record(domain, "AAAA")
    records.mx = await _resolve_record(domain, "MX")
    records.ns = await _resolve_record(domain, "NS")
    records.txt = await _resolve_record(domain, "TXT")
    records.cname = await _resolve_record(domain, "CNAME")
    records.soa = await _resolve_record(domain, "SOA")

    ptr_records: list[str] = []
    for ip_value in records.a:
        try:
            reversed_name = dns.reversename.from_address(ip_value)
            ptr_records.extend(await _resolve_record(str(reversed_name), "PTR"))
        except Exception:
            continue
    records.ptr = ptr_records

    providers = {provider for ip in records.a if (provider := _in_cdn_range(ip))}
    if providers and any(_in_cdn_range(ip) is None for ip in records.a):
        records.flags.append(
            Finding(
                id="DNS-ORIGIN-001",
                category="DNS",
                finding="Potential origin IP exposure detected for CDN-protected infrastructure.",
                risk="MEDIUM",
                score_impact=6,
                recommendation="Restrict origin access to CDN egress ranges only.",
                references=["https://owasp.org/www-project-top-ten/"],
            )
        )

    if not _spf_valid(records.txt):
        records.flags.append(
            Finding(
                id="DNS-SPF-001",
                category="DNS",
                finding="SPF record missing or malformed.",
                risk="MEDIUM",
                score_impact=5,
                recommendation="Publish a valid SPF record to reduce spoofing risks.",
                references=["https://www.rfc-editor.org/rfc/rfc7208"],
            )
        )

    dmarc_txt = await _resolve_record(f"_dmarc.{domain}", "TXT")
    if not _dmarc_valid(dmarc_txt):
        records.flags.append(
            Finding(
                id="DNS-DMARC-001",
                category="DNS",
                finding="DMARC record missing or invalid.",
                risk="MEDIUM",
                score_impact=5,
                recommendation="Configure DMARC with monitoring and enforcement policy.",
                references=["https://www.rfc-editor.org/rfc/rfc7489"],
            )
        )

    if not any("dkim" in entry.lower() for entry in records.txt + dmarc_txt):
        records.flags.append(
            Finding(
                id="DNS-DKIM-001",
                category="DNS",
                finding="No DKIM hints discovered in queried TXT records.",
                risk="LOW",
                score_impact=2,
                recommendation="Ensure DKIM selectors are configured for active mail domains.",
                references=["https://www.rfc-editor.org/rfc/rfc6376"],
            )
        )

    records.flags.extend(_detect_takeover(records.cname))

    if await _attempt_axfr(domain, records.ns):
        records.flags.append(
            Finding(
                id="DNS-AXFR-001",
                category="DNS",
                finding="Zone transfer appears enabled from at least one nameserver.",
                risk="HIGH",
                score_impact=8,
                recommendation="Restrict AXFR to authorized secondary DNS servers.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )
        )

    return records
