"""Markdown reporting for human-readable summaries."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import aiofiles

from core.models import ReconResult


def _badge(risk: str) -> str:
    return {
        "HIGH": "🔴 HIGH",
        "MEDIUM": "🟠 MEDIUM",
        "LOW": "🔵 LOW",
        "PASS": "🟢 PASS",
    }.get(risk, risk)


async def write_markdown_report(result: ReconResult, output_dir: Path) -> Path:
    """Write markdown report with core findings and recommendations."""

    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "report.md"
    formatted_timestamp = datetime.fromisoformat(
        str(result.timestamp).replace("Z", "+00:00")
    ).strftime("%B %d, %Y at %H:%M UTC")

    exposure = result.exposure
    findings = exposure.findings if exposure else []

    lines = [
        f"# {result.tool_name}",
        "",
        f"- **Domain:** {result.domain}",
        f"- **Date:** {formatted_timestamp}",
        f"- **Version:** {result.version}",
        "",
        "## Executive Summary",
        "",
    ]

    if exposure:
        lines.extend(
            [
                f"- **Exposure Score:** {exposure.score}/100",
                f"- **Exposure Level:** {exposure.label}",
                "",
                "## Score Breakdown",
                "",
                f"- SSL Issues: {exposure.breakdown.ssl_issues}/20",
                f"- Missing Headers: {exposure.breakdown.missing_headers}/20",
                f"- DNS Issues: {exposure.breakdown.dns_issues}/15",
                f"- Admin Exposure: {exposure.breakdown.admin_exposure}/15",
                f"- Tech Exposure: {exposure.breakdown.tech_exposure}/10",
                f"- Wayback Risks: {exposure.breakdown.wayback_risks}/10",
                f"- Surface Size: {exposure.breakdown.surface_size}/10",
                "",
            ]
        )

    lines.extend(["## Findings", "", "| ID | Category | Risk | Finding | Recommendation |", "|---|---|---|---|---|"])
    for finding in findings:
        lines.append(
            f"| {finding.id} | {finding.category} | {_badge(str(finding.risk))} | {finding.finding} | {finding.recommendation} |"
        )

    lines.extend(
        [
            "",
            "## Surface Highlights",
            "",
            f"- Subdomains discovered: {len(result.subdomains)}",
            f"- Internal links mapped: {len(result.surface.internal_links)}",
            f"- API-like routes: {len(result.surface.api_routes)}",
            f"- Admin paths: {len(result.surface.admin_paths)}",
            "",
            "## Ethical Use",
            "",
            "This report was generated passively for educational/authorized assessment purposes only.",
        ]
    )

    async with aiofiles.open(target, "w", encoding="utf-8") as handle:
        await handle.write("\n".join(lines))

    return target
