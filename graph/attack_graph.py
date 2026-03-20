"""Interactive attack surface graph generation using NetworkX and PyVis."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

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

DETAIL_PANEL = r"""
<style>
    #node-details-panel {
        position: fixed;
        right: 20px;
        bottom: 20px;
        width: min(520px, 92vw);
        background: rgba(13, 17, 23, 0.96);
        border: 1px solid #30363d;
        border-radius: 10px;
        box-shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
        color: #c9d1d9;
        z-index: 9999;
        font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif;
    }
    #node-details-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-bottom: 1px solid #30363d;
        font-size: 14px;
        font-weight: 700;
    }
    #node-details-actions {
        display: flex;
        gap: 8px;
    }
    #node-copy-btn, #node-clear-btn {
        border: 1px solid #30363d;
        background: #21262d;
        color: #c9d1d9;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 12px;
        cursor: pointer;
    }
    #node-copy-btn[disabled] {
        opacity: 0.45;
        cursor: not-allowed;
    }
    #node-details-body {
        padding: 12px;
        font-size: 13px;
        line-height: 1.5;
        max-height: 360px;
        overflow: auto;
        word-break: break-word;
        user-select: text;
        white-space: pre-wrap;
    }
</style>
<script>
    (function () {
        function copyText(value) {
            if (!value) {
                return Promise.resolve(false);
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                return navigator.clipboard.writeText(value).then(function () { return true; }).catch(function () { return false; });
            }
            var textArea = document.createElement('textarea');
            textArea.value = value;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            var ok = false;
            try {
                ok = document.execCommand('copy');
            } catch (e) {
                ok = false;
            }
            document.body.removeChild(textArea);
            return Promise.resolve(ok);
        }

        function initNodePanel() {
            if (typeof network === 'undefined' || typeof nodes === 'undefined') {
                return;
            }

            var panel = document.createElement('div');
            panel.id = 'node-details-panel';
            panel.innerHTML = ""
                + '<div id="node-details-header">'
                + '  <span id="node-details-title">Node Details</span>'
                + '  <div id="node-details-actions">'
                + '    <button id="node-copy-btn" disabled>Copy</button>'
                + '    <button id="node-clear-btn">Clear</button>'
                + '  </div>'
                + '</div>'
                + '<div id="node-details-body">Click a node to view full details.</div>';

            document.body.appendChild(panel);

            var titleEl = document.getElementById('node-details-title');
            var bodyEl = document.getElementById('node-details-body');
            var copyBtn = document.getElementById('node-copy-btn');
            var clearBtn = document.getElementById('node-clear-btn');
            var copyValue = '';

            function relationDetails(nodeId) {
                if (!nodeId || !allEdges) {
                    return '';
                }

                var incoming = 0;
                var outgoing = 0;
                var connected = [];
                var seen = {};

                Object.keys(allEdges).forEach(function (edgeId) {
                    var edge = allEdges[edgeId];
                    if (!edge) {
                        return;
                    }

                    if (edge.to === nodeId) {
                        incoming += 1;
                        if (edge.from && edge.from !== nodeId && !seen[edge.from]) {
                            seen[edge.from] = true;
                            connected.push(edge.from);
                        }
                    }

                    if (edge.from === nodeId) {
                        outgoing += 1;
                        if (edge.to && edge.to !== nodeId && !seen[edge.to]) {
                            seen[edge.to] = true;
                            connected.push(edge.to);
                        }
                    }
                });

                var neighborLabels = connected.slice(0, 12).map(function (neighborId) {
                    var neighbor = nodes.get(neighborId);
                    return neighbor ? (neighbor.label || neighbor.id || neighborId) : neighborId;
                });
                var hasMore = connected.length > 12;

                return ''
                    + '\n\nGraph Context:'
                    + '\n- Incoming edges: ' + incoming
                    + '\n- Outgoing edges: ' + outgoing
                    + '\n- Connected nodes: ' + connected.length
                    + (neighborLabels.length > 0 ? ('\n- Neighbors: ' + neighborLabels.join(', ') + (hasMore ? ', ...' : '')) : '');
            }

            function setContent(node) {
                if (!node) {
                    titleEl.textContent = 'Node Details';
                    bodyEl.textContent = 'Click a node to view full details.';
                    copyBtn.disabled = true;
                    copyValue = '';
                    return;
                }
                var typeLabel = node.detail_type || node.node_type || 'node';
                titleEl.textContent = typeLabel + ': ' + (node.label || node.id || 'unknown');
                bodyEl.textContent = (node.detail_body || node.title || node.id || '') + relationDetails(node.id);
                copyValue = node.copy_value || node.detail_body || node.title || '';
                copyBtn.disabled = !copyValue;
            }

            network.on('click', function (params) {
                if (!params.nodes || params.nodes.length === 0) {
                    return;
                }
                setContent(nodes.get(params.nodes[0]));
            });

            copyBtn.addEventListener('click', function () {
                copyText(copyValue).then(function (ok) {
                    var old = copyBtn.textContent;
                    copyBtn.textContent = ok ? 'Copied' : 'Copy failed';
                    setTimeout(function () { copyBtn.textContent = old; }, 1000);
                });
            });

            clearBtn.addEventListener('click', function () {
                setContent(null);
            });
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initNodePanel);
        } else {
            initNodePanel();
        }
    })();
</script>
"""


def _risk_size(score_impact: int) -> int:
    return min(60, 16 + score_impact * 4)


def _line(label: str, value: str | int | None) -> str:
    return f"{label}: {value if value not in (None, '') else '-'}"


def _url_detail_block(kind: str, url: str, base_domain: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or "-"
    is_internal = hostname == base_domain or hostname.endswith(f".{base_domain}")
    return "\n".join(
        [
            _line("Type", kind),
            _line("Full Value", url),
            _line("Scheme", parsed.scheme or "-"),
            _line("Hostname", hostname),
            _line("Port", parsed.port if parsed.port is not None else "default"),
            _line("Path", parsed.path or "/"),
            _line("Query", parsed.query or "-"),
            _line("Fragment", parsed.fragment or "-"),
            _line("Internal", "Yes" if is_internal else "No"),
        ]
    )


def _inject_detail_panel(output_path: Path) -> None:
    html = output_path.read_text(encoding="utf-8")
    if "node-details-panel" in html:
        return
    html = html.replace("</body>", f"{DETAIL_PANEL}\n</body>")
    output_path.write_text(html, encoding="utf-8")


def generate_attack_surface_graph(result: ReconResult, output_dir: Path) -> Path:
    """Build interactive attack surface graph and export standalone HTML."""

    output_dir.mkdir(parents=True, exist_ok=True)
    graph = nx.DiGraph()

    root_id = result.domain
    graph.add_node(
        root_id,
        label=result.domain,
        node_type="root",
        detail_type="Domain",
        detail_body=(
            "\n".join(
                [
                    _line("Type", "Root Domain"),
                    _line("Domain", result.domain),
                    _line("Timestamp", result.timestamp),
                    _line("Subdomains", len(result.subdomains)),
                    _line("Internal Links", len(result.surface.internal_links)),
                    _line("External Links", len(result.surface.external_links)),
                    _line("Scripts", len(result.surface.scripts)),
                    _line("Forms", len(result.surface.forms)),
                    _line("API Routes", len(result.surface.api_routes)),
                    _line("Admin Paths", len(result.surface.admin_paths)),
                ]
            )
        ),
        copy_value=result.domain,
        color=NODE_COLORS["root"],
        size=44,
    )

    for item in result.subdomains:
        node_id = f"sub::{item.name}"
        graph.add_node(
            node_id,
            label=item.name,
            node_type="subdomain",
            detail_type="Subdomain",
            detail_body="\n".join(
                [
                    _line("Type", "Subdomain"),
                    _line("Name", item.name),
                    _line("Status", item.status),
                    _line("IP", item.ip or "-"),
                    _line("Source", item.source),
                    _line("CDN/WAF", item.cdn_provider or "-"),
                    _line("Redirect Target", item.redirect_target or "-"),
                ]
            ),
            copy_value=item.name,
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
            detail_type="Admin URL" if is_admin else "URL",
            detail_body=_url_detail_block("Admin URL" if is_admin else "Internal URL", endpoint, result.domain),
            copy_value=endpoint,
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
            detail_type="External URL",
            detail_body=_url_detail_block("External URL", link, result.domain),
            copy_value=link,
            color=NODE_COLORS["external"],
            size=16,
            title=f"External URL: {link}",
        )
        graph.add_edge(root_id, node_id)

    for script in result.surface.scripts[:80]:
        node_id = f"js::{script}"
        script_details = _line("Type", "Script")
        if script.startswith("http://") or script.startswith("https://"):
            script_details = _url_detail_block("Script", script, result.domain)
        else:
            script_details = "\n".join(
                [
                    _line("Type", "Script"),
                    _line("Value", script),
                    _line("Nature", "Inline/Relative script reference"),
                ]
            )
        graph.add_node(
            node_id,
            label=script.split("//", 1)[-1][:40],
            node_type="js",
            detail_type="Script",
            detail_body=script_details,
            copy_value=script,
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
            detail_type="High Risk Finding",
            detail_body="\n".join(
                [
                    _line("Type", "High Risk Finding"),
                    _line("ID", finding.id),
                    _line("Category", finding.category),
                    _line("Risk", finding.risk),
                    _line("Score Impact", finding.score_impact),
                    _line("Finding", finding.finding),
                    _line("Recommendation", finding.recommendation),
                    _line("References", ", ".join(finding.references) if finding.references else "-"),
                ]
            ),
            copy_value=f"{finding.id}: {finding.finding}",
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
    _inject_detail_panel(output_path)
    return output_path
