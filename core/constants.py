"""Application constants for the passive reconnaissance toolkit."""

from __future__ import annotations

from enum import Enum

TOOL_NAME = "Attack Surface Mapping & Passive Reconnaissance Toolkit"
TOOL_VERSION = "1.0.0"

DEFAULT_USER_AGENT = (
    "ReconToolkit/1.0 (+Passive-Ethical-Assessment; contact: security@example.com)"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
}

RISK_ORDER = {"PASS": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

ADMIN_PATH_CANDIDATES = [
    "/admin",
    "/wp-admin",
    "/login",
    "/dashboard",
    "/cpanel",
    "/phpmyadmin",
    "/administrator",
    "/user/login",
]

WAYBACK_HIGH_RISK_KEYWORDS = [".env", ".git", "backup", "dump", ".sql", ".bak"]

CDN_PROVIDER_HINTS = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront", "x-amz-cf-id"],
}

SUBDOMAIN_SOURCES = ["crtsh", "hackertarget", "alienvault", "rapiddns", "wayback", "securitytrails"]


class RiskLevel(str, Enum):
    """Supported risk levels for findings."""

    PASS = "PASS"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SubdomainStatus(str, Enum):
    """State of a discovered subdomain."""

    LIVE = "LIVE"
    UNRESOLVABLE = "UNRESOLVABLE"
    REDIRECT = "REDIRECT"
