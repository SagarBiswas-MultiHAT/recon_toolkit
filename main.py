"""CLI entrypoint for Attack Surface Mapping & Passive Reconnaissance Toolkit."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.config_loader import ConfigError, load_config
from core.constants import TOOL_NAME, TOOL_VERSION
from core.logger import setup_logger
from core.models import ReconResult
from core.rate_limiter import AsyncRateLimiter
from graph.attack_graph import generate_attack_surface_graph
from modules.dns_analysis import analyze_dns
from modules.exposure_scorer import calculate_exposure_score
from modules.header_audit import audit_security_headers
from modules.ssl_tls import inspect_ssl_tls
from modules.subdomain_enum import enumerate_subdomains
from modules.surface_mapper import map_surface
from modules.tech_detection import detect_tech_stack
from modules.wayback import fetch_wayback_urls
from modules.whois_asn import lookup_whois_asn
from reporting.html_report import write_html_report
from reporting.json_report import write_json_report
from reporting.markdown_report import write_markdown_report

console = Console()


def _banner() -> Panel:
    return Panel.fit(
        f"[bold cyan]{TOOL_NAME}[/bold cyan]\n"
        f"[white]Version {TOOL_VERSION} • Passive • Ethical • Non-Destructive[/white]",
        border_style="blue",
    )


def _parse_csv(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return default
    return [entry.strip().lower() for entry in value.split(",") if entry.strip()]


def _module_allowed(name: str, selected: list[str]) -> bool:
    return "all" in selected or name in selected


async def _run(domain: str, config_path: str, output: list[str], selected_modules: list[str], skip_wayback: bool, no_graph: bool) -> None:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise SystemExit(1) from exc

    logger = setup_logger(config.general.log_level, config.general.output_dir)
    run_timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = Path(config.general.output_dir) / f"{domain}_{run_timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = AsyncRateLimiter()

    result = ReconResult(
        tool_name=TOOL_NAME,
        version=TOOL_VERSION,
        domain=domain,
        timestamp=datetime.now(UTC).isoformat(),
    )

    ip_seed = None

    console.print(_banner())

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        if config.modules.subdomain_enum and _module_allowed("subdomain", selected_modules):
            task = progress.add_task("Running subdomain enumeration...", total=None)
            try:
                result.subdomains, wildcard = await enumerate_subdomains(domain, config, rate_limiter)
                if wildcard:
                    logger.warning("Wildcard DNS resolution detected for %s", domain)
            except Exception as exc:
                logger.error("subdomain_enum failed: %s", exc)
            progress.remove_task(task)

        if config.modules.dns_analysis and _module_allowed("dns", selected_modules):
            task = progress.add_task("Analyzing DNS records...", total=None)
            try:
                result.dns = await analyze_dns(domain)
                if result.dns.a:
                    ip_seed = result.dns.a[0]
            except Exception as exc:
                logger.error("dns_analysis failed: %s", exc)
            progress.remove_task(task)

        if config.modules.whois_asn and _module_allowed("whois", selected_modules):
            task = progress.add_task("Collecting WHOIS/ASN data...", total=None)
            try:
                result.whois_asn = await lookup_whois_asn(domain, config, ip_seed)
            except Exception as exc:
                logger.error("whois_asn failed: %s", exc)
            progress.remove_task(task)

        if config.modules.ssl_tls and _module_allowed("ssl", selected_modules):
            task = progress.add_task("Inspecting SSL/TLS posture...", total=None)
            try:
                result.ssl_tls = await inspect_ssl_tls(domain, config)
            except Exception as exc:
                logger.error("ssl_tls failed: %s", exc)
            progress.remove_task(task)

        if config.modules.tech_detection and _module_allowed("tech", selected_modules):
            task = progress.add_task("Detecting technology stack...", total=None)
            try:
                result.tech = await detect_tech_stack(domain, config)
            except Exception as exc:
                logger.error("tech_detection failed: %s", exc)
            progress.remove_task(task)

        if config.modules.header_audit and _module_allowed("headers", selected_modules):
            task = progress.add_task("Auditing security headers...", total=None)
            try:
                result.headers = await audit_security_headers(domain, config)
            except Exception as exc:
                logger.error("header_audit failed: %s", exc)
            progress.remove_task(task)

        if config.modules.surface_mapper and _module_allowed("surface", selected_modules):
            task = progress.add_task("Mapping attack surface (depth=1)...", total=None)
            try:
                result.surface = await map_surface(domain, config)
            except Exception as exc:
                logger.error("surface_mapper failed: %s", exc)
            progress.remove_task(task)

        if not skip_wayback and config.modules.wayback and _module_allowed("wayback", selected_modules):
            task = progress.add_task("Querying Wayback archive...", total=None)
            try:
                result.wayback = await fetch_wayback_urls(domain, config, rate_limiter)
            except Exception as exc:
                logger.error("wayback failed: %s", exc)
            progress.remove_task(task)

    result.exposure = calculate_exposure_score(result)
    exposure = result.exposure
    if exposure is None:
        raise RuntimeError("Exposure scoring failed to return a score")

    generated: list[Path] = []
    if "json" in output:
        generated.append(await write_json_report(result, run_dir))
    if "md" in output:
        generated.append(await write_markdown_report(result, run_dir))
    if "html" in output:
        generated.append(await write_html_report(result, run_dir))

    if not no_graph and config.modules.attack_graph:
        generated.append(generate_attack_surface_graph(result, run_dir))

    table = Table(title="Recon Summary", box=box.SIMPLE_HEAVY)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Domain", domain)
    table.add_row("Subdomains", str(len(result.subdomains)))
    table.add_row("DNS Findings", str(len(result.dns.flags)))
    table.add_row("Header Findings", str(len(result.headers.findings)))
    table.add_row("Wayback Risk URLs", str(len(result.wayback.risky_urls)))
    table.add_row("Exposure Score", f"{exposure.score} ({exposure.label})")
    console.print(table)

    risk_color = "green"
    if exposure.score > 75:
        risk_color = "red"
    elif exposure.score > 50:
        risk_color = "orange3"
    elif exposure.score > 25:
        risk_color = "yellow"

    console.print(
        Panel.fit(
            f"[bold {risk_color}]Final Exposure Score: {exposure.score}/100[/bold {risk_color}]\n"
            f"[white]{exposure.label}[/white]",
            border_style=risk_color,
        )
    )

    console.print("[bold]Generated outputs:[/bold]")
    for item in generated:
        console.print(f" - {item}")


@click.command()
@click.option("--domain", required=True, help="Target domain (e.g., example.com)")
@click.option("--output", default="html,json,md", help="Output formats: html,json,md")
@click.option("--modules", "modules_csv", default="all", help="Run specific modules: dns,ssl,headers")
@click.option("--config", "config_path", default="config.yaml", help="Path to YAML configuration file")
@click.option("--skip-wayback", is_flag=True, help="Skip Wayback module")
@click.option("--no-graph", is_flag=True, help="Do not generate attack surface graph")
def cli(domain: str, output: str, modules_csv: str, config_path: str, skip_wayback: bool, no_graph: bool) -> None:
    """Run passive attack surface mapping and reconnaissance workflow."""

    outputs = _parse_csv(output, ["html", "json", "md"])
    selected_modules = _parse_csv(modules_csv, ["all"])
    asyncio.run(_run(domain, config_path, outputs, selected_modules, skip_wayback, no_graph))


if __name__ == "__main__":
    cli()
