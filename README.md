# mcp-audit

Security scanner for MCP (Model Context Protocol) server configurations. Think `npm audit` but for MCP.

Detects tool poisoning, credential leaks, supply chain risks, and misconfigurations in MCP client configs.

## Install

```bash
# Zero-install via uvx
uvx mcp-audit scan

# Or install with pip/uv
pip install mcp-audit
uv add mcp-audit
```

## Quick Start

```bash
# Auto-discover and scan all MCP configs on your system
mcp-audit scan

# Scan a specific config file
mcp-audit scan --config ~/.cursor/mcp.json

# JSON output
mcp-audit scan --output json

# SARIF output (for CI integration)
mcp-audit scan --output sarif --output-file report.sarif

# Only report HIGH and CRITICAL findings
mcp-audit scan --min-severity HIGH

# List all available checks
mcp-audit list-checks
```

## Security Checks

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| MCP001 | Plaintext secrets in env | CRITICAL | Detects API keys, tokens, and high-entropy secrets in environment variables |
| MCP002 | Credentials in args | CRITICAL | Detects secrets passed as command-line arguments |
| MCP003 | Wildcard autoApprove | CRITICAL | Flags `autoApprove: "*"` that bypasses all user confirmation |
| MCP004 | Tool poisoning in desc | HIGH | Detects HTML injection, exfiltration paths, social engineering in configs |
| MCP005 | Full-schema poisoning | HIGH | Detects poisoning patterns in tool schema definitions |
| MCP006 | Broad filesystem access | HIGH | Flags filesystem servers with overly broad paths like `/` or `~` |
| MCP007 | Unverified npx packages | MEDIUM | Flags `npx -y` packages without pinned versions |
| MCP008 | Missing HTTPS | MEDIUM | Detects insecure HTTP URLs in server configurations |
| MCP009 | World-readable config | MEDIUM | Flags config files with world-readable permissions |
| MCP010 | Unresolved env var refs | LOW | Detects `${VAR}` references that can't be resolved |
| MCP011 | Known vulnerable packages | HIGH | Checks packages against a database of known CVEs |
| MCP012 | Rug pull detection | MEDIUM | Detects tool definition changes between scans |

## Auto-Discovery

mcp-audit automatically finds config files for these MCP clients:

| Client | Config Path |
|--------|-------------|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%/Claude/claude_desktop_config.json` |
| Claude Code | `.mcp.json` (cwd), `~/.claude.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` |

## Output Formats

### Table (default)

Rich terminal output with color-coded severity:

```
$ mcp-audit scan --config vulnerable.json
                         MCP Security Findings
┏━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Severity ┃ Check  ┃ Server      ┃ Title                  ┃ Evidence  ┃
┡━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ CRITICAL │ MCP001 │ leaky-srv   │ Plaintext secrets      │ env.KEY = │
│ CRITICAL │ MCP003 │ leaky-srv   │ Wildcard autoApprove   │ ['*']     │
│ HIGH     │ MCP006 │ broad-fs    │ Broad filesystem       │ arg: /    │
└──────────┴────────┴─────────────┴────────────────────────┴───────────┘
Found 3 finding(s): 2 critical, 1 high
```

### JSON

```bash
mcp-audit scan --output json
```

### SARIF 2.1.0

Standard format for CI/CD integration (GitHub Code Scanning, etc.):

```bash
mcp-audit scan --output sarif --output-file results.sarif
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or no configs found) |
| 1 | Findings detected |
| 2 | Error (invalid config, missing file) |

## Secret Patterns Detected

MCP001 and MCP002 scan for these patterns:

- GitHub PAT: `ghp_[A-Za-z0-9]{36}`
- OpenAI key: `sk-[A-Za-z0-9]{48}`
- AWS access key: `AKIA[0-9A-Z]{16}`
- JWT tokens: `eyJhbGci...`
- Supabase keys: `sbp_[a-f0-9]{40}`
- High-entropy strings (Shannon entropy > 4.5, length > 20)
- Generic `password=`, `secret=`, `token=` patterns

## Known CVEs (MCP011)

| Package | CVE | Severity |
|---------|-----|----------|
| mcp-remote | CVE-2025-6514 | CRITICAL |
| @modelcontextprotocol/inspector | CVE-2025-49596 | CRITICAL |
| framelink-figma-mcp | CVE-2025-53967 | HIGH |
| mcp-server-git | CVE-2025-68143 | CRITICAL |
| gemini-mcp-tool | CVE-2026-0755 | CRITICAL |

## Development

```bash
# Clone and install
git clone https://github.com/chaaiitanya/mcp-audit.git
cd mcp-audit
uv sync

# Run tests
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/mcp_audit/
```

## Architecture

- **CLI**: Typer with type hints
- **Config models**: Pydantic v2
- **Checks**: Each check is a separate file inheriting `BaseCheck`, auto-registered via `@register_check`
- **Output**: Rich (table), JSON, SARIF 2.1.0
- **Packaging**: uv + hatchling, distributed via PyPI

## License

MIT
