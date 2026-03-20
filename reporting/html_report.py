"""HTML reporting renderer using Jinja2 templates."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import aiofiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import ReconResult


def _jinja_environment(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


async def write_html_report(result: ReconResult, output_dir: Path) -> Path:
    """Render polished HTML report from toolkit results."""

    output_dir.mkdir(parents=True, exist_ok=True)
    template_dir = Path(__file__).resolve().parent / "templates"
    env = _jinja_environment(template_dir)
    template = env.get_template("report.html.jinja")
    formatted_timestamp = datetime.fromisoformat(
        str(result.timestamp).replace("Z", "+00:00")
    ).strftime("%B %d, %Y at %H:%M UTC")
    result = result.model_copy(update={"timestamp": formatted_timestamp})

    html = template.render(result=result)
    target = output_dir / "report.html"

    async with aiofiles.open(target, "w", encoding="utf-8") as handle:
        await handle.write(html)

    return target
