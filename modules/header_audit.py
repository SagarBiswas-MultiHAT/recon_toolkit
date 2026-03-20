"""Security header audit module."""

from __future__ import annotations

import aiohttp

from core.constants import DEFAULT_HEADERS
from core.models import Finding, HeaderAuditResult, ToolkitConfig


async def audit_security_headers(domain: str, config: ToolkitConfig) -> HeaderAuditResult:
    """Evaluate key security headers and return findings."""

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    result = HeaderAuditResult()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(f"https://{domain}", headers=DEFAULT_HEADERS) as response:
            result.headers = {k.lower(): v for k, v in response.headers.items()}

    headers = result.headers

    if "content-security-policy" not in headers:
        result.findings.append(
            Finding(
                id="HDR-001",
                category="Security Headers",
                finding="Content-Security-Policy header is missing",
                risk="HIGH",
                score_impact=8,
                recommendation="Implement a strict CSP policy tailored to required assets.",
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        )
    else:
        csp = headers["content-security-policy"].lower()
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            result.findings.append(
                Finding(
                    id="HDR-002",
                    category="Security Headers",
                    finding="CSP includes unsafe-inline or unsafe-eval directives",
                    risk="MEDIUM",
                    score_impact=5,
                    recommendation="Reduce unsafe CSP directives and use nonces/hashes.",
                    references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
                )
            )

    if "strict-transport-security" not in headers:
        result.findings.append(
            Finding(
                id="HDR-003",
                category="Security Headers",
                finding="Strict-Transport-Security header is missing",
                risk="HIGH",
                score_impact=8,
                recommendation="Enable HSTS with an adequate max-age.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            )
        )

    if "x-frame-options" not in headers:
        result.findings.append(
            Finding(
                id="HDR-004",
                category="Security Headers",
                finding="X-Frame-Options header is missing",
                risk="MEDIUM",
                score_impact=5,
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        )

    if headers.get("access-control-allow-origin", "") == "*":
        result.findings.append(
            Finding(
                id="HDR-005",
                category="Security Headers",
                finding="CORS policy allows wildcard origin (*)",
                risk="HIGH",
                score_impact=8,
                recommendation="Restrict CORS origins to trusted domains.",
                references=["https://cheatsheetseries.owasp.org/"],
            )
        )

    for header_name in [
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    ]:
        if header_name not in headers:
            result.findings.append(
                Finding(
                    id=f"HDR-{100 + len(result.findings)}",
                    category="Security Headers",
                    finding=f"{header_name} header is missing",
                    risk="LOW",
                    score_impact=2,
                    recommendation=f"Set a secure default for {header_name}.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )

    return result
