"""Interactive attack surface graph generation using NetworkX and PyVis."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
from pyvis.network import Network

from core.models import ReconResult

NODE_COLORS = {
    "root": "#58a6ff",
    "subdomain": "#2a9d8f",
    "endpoint": "#8b949e",
    "admin": "#ff4d4f",
    "external": "#f39c12",
    "js": "#f1c40f",
}


def _risk_size(score_impact: int) -> int:
    return min(60, 16 + score_impact * 4)


def generate_attack_surface_graph(result: ReconResult, output_dir: Path) -> Path:
    """Build interactive attack surface graph and export standalone HTML."""

    output_dir.mkdir(parents=True, exist_ok=True)
    graph = nx.DiGraph()

    root_id = result.domain
    graph.add_node(root_id, label=result.domain, node_type="root", color=NODE_COLORS["root"], size=44)

    for item in result.subdomains:
        node_id = f"sub::{item.name}"
        graph.add_node(
            node_id,
            label=item.name,
            node_type="subdomain",
            color=NODE_COLORS["subdomain"],
            size=24,
            title=f"Status: {item.status} | IP: {item.ip or '-'}",
        )
        graph.add_edge(root_id, node_id)

    for endpoint in result.surface.internal_links[:120]:
        node_id = f"ep::{endpoint}"
        is_admin = any(path in endpoint.lower() for path in result.surface.admin_paths)
        node_type = "admin" if is_admin else "endpoint"
        graph.add_node(
            node_id,
            label=endpoint.split("//", 1)[-1][:40],
            node_type=node_type,
            color=NODE_COLORS[node_type],
            size=28 if is_admin else 16,
            title=f"URL: {endpoint}",
        )
        graph.add_edge(root_id, node_id)

    for link in result.surface.external_links[:80]:
        node_id = f"ext::{link}"
        graph.add_node(
            node_id,
            label=link.split("//", 1)[-1][:40],
            node_type="external",
            color=NODE_COLORS["external"],
            size=16,
            title=f"External URL: {link}",
        )
        graph.add_edge(root_id, node_id)

    for script in result.surface.scripts[:80]:
        node_id = f"js::{script}"
        graph.add_node(
            node_id,
            label=script.split("//", 1)[-1][:40],
            node_type="js",
            color=NODE_COLORS["js"],
            size=14,
            title=f"Script: {script}",
        )
        graph.add_edge(root_id, node_id)

    for finding in (result.exposure.findings if result.exposure else []):
        if str(finding.risk) != "HIGH":
            continue
        finding_id = f"risk::{finding.id}"
        graph.add_node(
            finding_id,
            label=finding.id,
            node_type="endpoint",
            color="#ff4d4f",
            size=_risk_size(finding.score_impact),
            title=f"{finding.finding}\nRisk: {finding.risk}",
        )
        graph.add_edge(root_id, finding_id)

    vis = Network(height="900px", width="100%", directed=True, bgcolor="#0d1117", font_color="#c9d1d9")
    vis.from_nx(graph)
    vis.barnes_hut(gravity=-30000, central_gravity=0.35, spring_length=120)

    output_path = output_dir / "attack_surface_graph.html"
    vis.write_html(str(output_path), notebook=False)
    return output_path
