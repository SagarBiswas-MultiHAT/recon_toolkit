"""JSON reporting for machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import aiofiles

from core.models import ReconResult


async def write_json_report(result: ReconResult, output_dir: Path) -> Path:
    """Write JSON report to output directory."""

    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "report.json"
    payload = result.model_dump(mode="json")
    payload["timestamp"] = datetime.fromisoformat(
        str(result.timestamp).replace("Z", "+00:00")
    ).strftime("%B %d, %Y at %H:%M UTC")

    async with aiofiles.open(target, "w", encoding="utf-8") as handle:
        await handle.write(json.dumps(payload, indent=2))

    return target
