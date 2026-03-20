"""Passive SSL/TLS certificate inspection module."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from core.constants import DEFAULT_HEADERS
from core.models import Finding, SslTlsData, ToolkitConfig


def _parse_certificate(cert_der: bytes) -> tuple[str | None, str | None, list[str], datetime | None]:
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    san_entries: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_entries = [entry.value for entry in san.value]
    except x509.ExtensionNotFound:
        pass

    not_after = cert.not_valid_after_utc
    return issuer, subject, san_entries, not_after


def _fetch_cert_and_tls(hostname: str, port: int = 443) -> tuple[bytes, str | None]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ValueError("No peer certificate returned")
            version = tls_sock.version()
            return cert_der, version


def _self_signed(issuer: str | None, subject: str | None) -> bool:
    return bool(issuer and subject and issuer == subject)


async def _hsts_present(domain: str, timeout: int) -> bool:
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        try:
            async with session.get(f"https://{domain}", headers=DEFAULT_HEADERS) as response:
                return "strict-transport-security" in {
                    key.lower(): value for key, value in response.headers.items()
                }
        except Exception:
            return False


def _flag_internal_san(san_entries: list[str]) -> bool:
    tokens = ["internal", "dev", "staging", "test", "local"]
    return any(any(token in san.lower() for token in tokens) for san in san_entries)


async def inspect_ssl_tls(domain: str, config: ToolkitConfig) -> SslTlsData:
    """Inspect TLS certificate metadata and passive security signals."""

    data = SslTlsData()

    try:
        cert_der, tls_version = await asyncio.to_thread(_fetch_cert_and_tls, domain)
        issuer, subject, sans, not_after = _parse_certificate(cert_der)
        data.issuer = issuer
        data.subject = subject
        data.san_entries = sans
        data.not_after = not_after.isoformat() if not_after else None
        data.tls_version = tls_version
        data.self_signed = _self_signed(issuer, subject)
        data.wildcard_cert = any(san.startswith("*.") for san in sans)

        if not_after:
            data.days_remaining = (not_after - datetime.now(UTC)).days
    except Exception:
        data.flags.append(
            Finding(
                id="SSL-ERR-001",
                category="SSL/TLS",
                finding="Unable to retrieve certificate information from endpoint.",
                risk="MEDIUM",
                score_impact=5,
                recommendation="Verify HTTPS service availability and certificate chain.",
                references=["https://cheatsheetseries.owasp.org/"],
            )
        )
        return data

    data.hsts_present = await _hsts_present(domain, config.general.request_timeout)

    if data.days_remaining is not None and data.days_remaining < 30:
        data.flags.append(
            Finding(
                id="SSL-EXP-001",
                category="SSL/TLS",
                finding=f"Certificate expires in {data.days_remaining} days.",
                risk="HIGH",
                score_impact=8,
                recommendation="Renew certificate before expiry and automate renewal checks.",
                references=["https://owasp.org/www-project-top-ten/"],
            )
        )

    if data.tls_version in {"TLSv1", "TLSv1.1"}:
        data.flags.append(
            Finding(
                id="SSL-TLS-001",
                category="SSL/TLS",
                finding=f"Deprecated TLS version supported: {data.tls_version}",
                risk="MEDIUM",
                score_impact=6,
                recommendation="Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
                references=["https://www.rfc-editor.org/rfc/rfc8996"],
            )
        )

    if data.self_signed:
        data.flags.append(
            Finding(
                id="SSL-SELF-001",
                category="SSL/TLS",
                finding="Certificate appears self-signed.",
                risk="HIGH",
                score_impact=8,
                recommendation="Use a trusted public CA certificate for internet-facing services.",
                references=["https://cheatsheetseries.owasp.org/"],
            )
        )

    if _flag_internal_san(data.san_entries):
        data.flags.append(
            Finding(
                id="SSL-SAN-001",
                category="SSL/TLS",
                finding="SAN entries reveal internal/dev naming conventions.",
                risk="MEDIUM",
                score_impact=5,
                recommendation="Avoid exposing non-production hostnames in public certificates.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )
        )

    return data
