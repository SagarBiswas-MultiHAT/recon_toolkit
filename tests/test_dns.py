import pytest

from modules import dns_analysis


@pytest.mark.asyncio
async def test_dns_analysis_spf_dmarc_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(domain: str, record_type: str) -> list[str]:
        mapping = {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "MX": [],
            "NS": ["ns1.example.com."],
            "TXT": [],
            "CNAME": ["unclaimed.github.io."],
            "SOA": ["ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"],
            "PTR": [],
        }
        return mapping.get(record_type, [])

    async def fake_axfr(domain: str, nameservers: list[str]) -> bool:
        return False

    monkeypatch.setattr(dns_analysis, "_resolve_record", fake_resolve)
    monkeypatch.setattr(dns_analysis, "_attempt_axfr", fake_axfr)

    result = await dns_analysis.analyze_dns("example.com")
    finding_ids = {finding.id for finding in result.flags}

    assert "DNS-SPF-001" in finding_ids
    assert "DNS-DMARC-001" in finding_ids
    assert "DNS-TAKEOVER-001" in finding_ids
