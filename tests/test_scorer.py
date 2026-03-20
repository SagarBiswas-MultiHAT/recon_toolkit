from core.constants import RiskLevel
from core.models import Finding, HeaderAuditResult, ReconResult, SslTlsData
from modules.exposure_scorer import calculate_exposure_score


def test_exposure_score_calculation() -> None:
    result = ReconResult(
        tool_name="tool",
        version="1",
        domain="example.com",
        timestamp="2026-03-20T00:00:00Z",
    )
    result.ssl_tls = SslTlsData(
        flags=[
            Finding(
                id="SSL-1",
                category="SSL/TLS",
                finding="Self-signed cert",
                risk=RiskLevel.HIGH,
                score_impact=8,
                recommendation="Use trusted CA",
                references=[],
            )
        ]
    )
    result.headers = HeaderAuditResult(
        findings=[
            Finding(
                id="HDR-1",
                category="Security Headers",
                finding="Missing CSP",
                risk=RiskLevel.HIGH,
                score_impact=8,
                recommendation="Add CSP",
                references=[],
            )
        ]
    )
    result.surface.admin_paths = ["/admin", "/login"]

    exposure = calculate_exposure_score(result)

    assert 0 <= exposure.score <= 100
    assert exposure.label in {
        "LOW EXPOSURE",
        "MODERATE EXPOSURE",
        "HIGH EXPOSURE",
        "CRITICAL EXPOSURE",
    }
    assert exposure.breakdown.admin_exposure > 0
