"""SARIF 2.1.0 output formatter."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mcp_audit.checks.base import Finding, Severity


class SARIFMessage(BaseModel):
    """SARIF message object."""

    text: str


class SARIFArtifactLocation(BaseModel):
    """SARIF artifact location."""

    uri: str


class SARIFPhysicalLocation(BaseModel):
    """SARIF physical location."""

    artifactLocation: SARIFArtifactLocation


class SARIFLocation(BaseModel):
    """SARIF location wrapper."""

    physicalLocation: SARIFPhysicalLocation


class SARIFResult(BaseModel):
    """A single SARIF result entry."""

    ruleId: str
    level: str
    message: SARIFMessage
    locations: list[SARIFLocation] = Field(default_factory=list)


class SARIFRule(BaseModel):
    """SARIF rule definition."""

    id: str
    name: str
    shortDescription: SARIFMessage


class SARIFDriver(BaseModel):
    """SARIF tool driver."""

    name: str = "mcp-audit"
    version: str = "0.1.0"
    rules: list[SARIFRule] = Field(default_factory=list)


class SARIFTool(BaseModel):
    """SARIF tool wrapper."""

    driver: SARIFDriver = Field(default_factory=SARIFDriver)


class SARIFRun(BaseModel):
    """A single SARIF run."""

    tool: SARIFTool = Field(default_factory=SARIFTool)
    results: list[SARIFResult] = Field(default_factory=list)


class SARIFReport(BaseModel):
    """Top-level SARIF 2.1.0 report."""

    model_config = ConfigDict(populate_by_name=True)

    schema_uri: str = Field(
        default="https://json.schemastore.org/sarif-2.1.0.json",
        alias="$schema",
    )
    version: str = "2.1.0"
    runs: list[SARIFRun] = Field(default_factory=list)


def _severity_to_level(severity: Severity) -> str:
    """Map Finding severity to SARIF level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def build_sarif(findings: list[Finding], source_path: Path | None = None) -> str:
    """Build a SARIF 2.1.0 JSON string from a list of findings."""
    uri = source_path.as_uri() if source_path else "file:///unknown"

    # Deduplicate rules by check_id
    seen_rules: dict[str, SARIFRule] = {}
    results: list[SARIFResult] = []

    for finding in findings:
        if finding.check_id not in seen_rules:
            seen_rules[finding.check_id] = SARIFRule(
                id=finding.check_id,
                name=finding.title,
                shortDescription=SARIFMessage(text=finding.title),
            )

        results.append(
            SARIFResult(
                ruleId=finding.check_id,
                level=_severity_to_level(finding.severity),
                message=SARIFMessage(text=finding.description),
                locations=[
                    SARIFLocation(
                        physicalLocation=SARIFPhysicalLocation(
                            artifactLocation=SARIFArtifactLocation(uri=uri),
                        )
                    )
                ],
            )
        )

    report = SARIFReport(
        runs=[
            SARIFRun(
                tool=SARIFTool(
                    driver=SARIFDriver(rules=list(seen_rules.values())),
                ),
                results=results,
            )
        ]
    )

    return report.model_dump_json(by_alias=True, indent=2)
