"""Exposure scoring engine for consolidated recon findings."""

from __future__ import annotations

from core.constants import RiskLevel
from core.models import ExposureScore, Finding, ReconResult, ScoreBreakdown


def _clamp(value: int, max_points: int) -> int:
    return max(0, min(value, max_points))


def _risk_points(risk: RiskLevel) -> int:
    table = {
        RiskLevel.HIGH: 4,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 1,
        RiskLevel.PASS: 0,
    }
    return table[risk]


def _score_label(score: int) -> str:
    if score <= 25:
        return "LOW EXPOSURE"
    if score <= 50:
        return "MODERATE EXPOSURE"
    if score <= 75:
        return "HIGH EXPOSURE"
    return "CRITICAL EXPOSURE"


def _base_wayback_findings(risky_urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in risky_urls:
        findings.append(
            Finding(
                id="WB-001",
                category="Wayback",
                finding=f"Historical high-risk artifact discovered: {url}",
                risk=RiskLevel.HIGH,
                score_impact=4,
                recommendation="Confirm file no longer exists and rotate potentially exposed secrets.",
                references=["https://owasp.org/www-project-top-ten/"],
            )
        )
    return findings


def calculate_exposure_score(result: ReconResult) -> ExposureScore:
    """Calculate weighted score and normalize to 0-100 range."""

    ssl_findings = result.ssl_tls.flags
    header_findings = result.headers.findings
    dns_findings = result.dns.flags

    admin_count = len(result.surface.admin_paths)
    tech_disclosure = (
        len(result.tech.runtime) + len(result.tech.frameworks) + len(result.tech.cms) + len(result.tech.web_server)
    )
    wayback_findings = _base_wayback_findings(result.wayback.risky_urls)

    ssl_score = _clamp(sum(_risk_points(item.risk) for item in ssl_findings), 20)
    header_score = _clamp(sum(_risk_points(item.risk) for item in header_findings), 20)
    dns_score = _clamp(sum(_risk_points(item.risk) for item in dns_findings), 15)
    admin_score = _clamp(admin_count * 3, 15)
    tech_score = _clamp(tech_disclosure, 10)
    wayback_score = _clamp(len(wayback_findings) * 3, 10)

    surface_size = len(result.surface.internal_links) + len(result.surface.forms) + len(result.surface.api_routes)
    surface_score = _clamp(surface_size // 10, 10)

    total = ssl_score + header_score + dns_score + admin_score + tech_score + wayback_score + surface_score

    findings: list[Finding] = []
    findings.extend(ssl_findings)
    findings.extend(header_findings)
    findings.extend(dns_findings)
    findings.extend(wayback_findings)

    exposure = ExposureScore(
        score=total,
        label=_score_label(total),
        breakdown=ScoreBreakdown(
            ssl_issues=ssl_score,
            missing_headers=header_score,
            dns_issues=dns_score,
            admin_exposure=admin_score,
            tech_exposure=tech_score,
            wayback_risks=wayback_score,
            surface_size=surface_score,
        ),
        findings=findings,
    )

    return exposure
