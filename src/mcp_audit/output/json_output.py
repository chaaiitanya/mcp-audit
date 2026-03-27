"""JSON output formatter for findings."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from mcp_audit.checks.base import Finding


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    d = dataclasses.asdict(finding)
    d["severity"] = finding.severity.name
    return d


def build_json(findings: list[Finding]) -> str:
    """Build a JSON string from a list of findings."""
    return json.dumps([_finding_to_dict(f) for f in findings], indent=2)
