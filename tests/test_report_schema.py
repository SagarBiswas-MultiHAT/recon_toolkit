import json
from pathlib import Path

import pytest

from core.models import ReconResult
from reporting.json_report import write_json_report


@pytest.mark.asyncio
async def test_json_report_schema(tmp_path: Path) -> None:
    result = ReconResult(
        tool_name="Recon",
        version="1.0",
        domain="example.com",
        timestamp="2026-03-20T00:00:00Z",
    )

    report_path = await write_json_report(result, tmp_path)
    data = json.loads(report_path.read_text(encoding="utf-8"))

    for key in ["tool_name", "version", "domain", "timestamp", "subdomains", "dns", "surface"]:
        assert key in data
