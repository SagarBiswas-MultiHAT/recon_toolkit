"""Typed data models shared across modules and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.constants import RiskLevel, SubdomainStatus


class GeneralConfig(BaseModel):
    """General runtime configuration."""

    output_dir: str = "./output"
    log_level: str = "INFO"
    request_timeout: int = 10
    max_concurrent_requests: int = 5


class ApiKeysConfig(BaseModel):
    """Optional API keys used by enrichment sources."""

    securitytrails: str = ""
    shodan: str = ""
    virustotal: str = ""


class ModulesConfig(BaseModel):
    """Feature toggle configuration."""

    subdomain_enum: bool = True
    dns_analysis: bool = True
    whois_asn: bool = True
    ssl_tls: bool = True
    tech_detection: bool = True
    header_audit: bool = True
    surface_mapper: bool = True
    wayback: bool = True
    attack_graph: bool = True


class RateLimitsConfig(BaseModel):
    """Configurable, polite delays and concurrency settings."""

    crtsh_delay: float = 1.0
    wayback_delay: float = 0.5
    dns_concurrent: int = 10


class ToolkitConfig(BaseModel):
    """Root configuration model loaded from YAML."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    api_keys: ApiKeysConfig = Field(default_factory=ApiKeysConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)


class Finding(BaseModel):
    """Single security finding record."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    category: str
    finding: str
    risk: RiskLevel
    score_impact: int
    recommendation: str
    references: list[str] = Field(default_factory=list)


class SubdomainResult(BaseModel):
    """Normalized subdomain discovery result."""

    model_config = ConfigDict(use_enum_values=True)

    name: str
    status: SubdomainStatus
    ip: str | None = None
    source: str = "unknown"
    cdn_provider: str | None = None
    redirect_target: str | None = None


class DnsRecordSet(BaseModel):
    """Aggregated DNS records and DNS security analysis."""

    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    soa: list[str] = Field(default_factory=list)
    ptr: list[str] = Field(default_factory=list)
    flags: list[Finding] = Field(default_factory=list)


class WhoisAsnData(BaseModel):
    """WHOIS and ASN/IP context."""

    registrar: str | None = None
    creation_date: str | None = None
    expiry_date: str | None = None
    registrant_country: str | None = None
    asn: str | None = None
    organization: str | None = None
    ip_country: str | None = None
    ip_city: str | None = None
    reverse_ip_domains: list[str] = Field(default_factory=list)
    expiring_soon: bool = False


class SslTlsData(BaseModel):
    """TLS and certificate metadata."""

    issuer: str | None = None
    subject: str | None = None
    san_entries: list[str] = Field(default_factory=list)
    not_after: str | None = None
    days_remaining: int | None = None
    tls_version: str | None = None
    self_signed: bool = False
    wildcard_cert: bool = False
    hsts_present: bool = False
    flags: list[Finding] = Field(default_factory=list)


class TechStackData(BaseModel):
    """Detected technologies and surface hints."""

    web_server: list[str] = Field(default_factory=list)
    runtime: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    cms: list[str] = Field(default_factory=list)
    cdn_waf: list[str] = Field(default_factory=list)
    frontend: list[str] = Field(default_factory=list)
    analytics: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class HeaderAuditResult(BaseModel):
    """HTTP security header posture."""

    headers: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class SurfaceMapData(BaseModel):
    """Attack surface extraction results."""

    internal_links: list[str] = Field(default_factory=list)
    external_links: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    forms: list[str] = Field(default_factory=list)
    api_routes: list[str] = Field(default_factory=list)
    admin_paths: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    robots_disallow: list[str] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    security_txt: dict[str, str] = Field(default_factory=dict)


class WaybackData(BaseModel):
    """Historical URL intelligence from the Wayback machine."""

    urls: list[str] = Field(default_factory=list)
    historical_subdomains: list[str] = Field(default_factory=list)
    risky_urls: list[str] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    """Category-level score details."""

    ssl_issues: int = 0
    missing_headers: int = 0
    dns_issues: int = 0
    admin_exposure: int = 0
    tech_exposure: int = 0
    wayback_risks: int = 0
    surface_size: int = 0


class ExposureScore(BaseModel):
    """Final exposure score output."""

    score: int
    label: str
    breakdown: ScoreBreakdown
    findings: list[Finding] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Top-level object used by reporting modules."""

    tool_name: str
    version: str
    domain: str
    timestamp: str
    subdomains: list[SubdomainResult] = Field(default_factory=list)
    dns: DnsRecordSet = Field(default_factory=DnsRecordSet)
    whois_asn: WhoisAsnData = Field(default_factory=WhoisAsnData)
    ssl_tls: SslTlsData = Field(default_factory=SslTlsData)
    tech: TechStackData = Field(default_factory=TechStackData)
    headers: HeaderAuditResult = Field(default_factory=HeaderAuditResult)
    surface: SurfaceMapData = Field(default_factory=SurfaceMapData)
    wayback: WaybackData = Field(default_factory=WaybackData)
    exposure: ExposureScore | None = None


@dataclass(slots=True)
class GraphNode:
    """Node model for attack surface graph rendering."""

    node_id: str
    label: str
    node_type: str
    url: str | None = None
    risk: RiskLevel = RiskLevel.LOW
    status_code: int | None = None
    size: int = 20
    color: str = "#58a6ff"


@dataclass(slots=True)
class GraphEdge:
    """Edge model for attack surface graph rendering."""

    source: str
    target: str
    title: str = ""


@dataclass(slots=True)
class RuntimeContext:
    """Runtime context shared by orchestrator and modules."""

    domain: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    output_dir: str = "./output"
    metadata: dict[str, Any] = field(default_factory=dict)
