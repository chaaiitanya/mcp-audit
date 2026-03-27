# mcp-audit — Claude Code context

## What this is
Open-source CLI security scanner for MCP (Model Context Protocol) server configs.
Think "npm audit" but for MCP. Detects tool poisoning, credential leaks,
supply chain risks, and misconfigurations.

## Stack
- Python 3.10+, uv (packaging), Typer (CLI), Rich (terminal output)
- Pydantic v2 (config models), jsonschema (tool schema validation)
- Output formats: Rich table (default), JSON, SARIF 2.1.0
- Distributed via PyPI and uvx zero-install

## Coding patterns to follow
- CLI: Typer with type hints, never argparse or raw Click
- Packaging: uv + hatchling, never setuptools or poetry
- Validation: Pydantic v2 always, never dataclasses for config models
- Testing: pytest with CliRunner for CLI tests, tmp_path for file fixtures
- Output: Rich for terminal, never print() directly
- Paths: platformdirs always, never hardcoded ~ or os.path
- Checks: one class per file, @register_check decorator, BaseCheck ABC
- Secrets regex: use re.compile at module level, never inline in functions
- SARIF: build with Pydantic models, validate against SARIF 2.1.0 schema in tests

## Architecture rules
- All checks inherit from BaseCheck in src/mcp_audit/checks/base.py
- Each check is a separate file in src/mcp_audit/checks/builtin/
- Checks are auto-registered via @register_check decorator
- Finding dataclass fields: check_id, severity, title, description,
  server_name, remediation, evidence
- Severity enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- CLI exit codes: 0 = clean, 1 = findings found, 2 = error
- No cloud API calls — scanner must work fully offline
- No LLM calls in core scanner — keep it fast and deterministic

## All 12 checks
| ID     | Name                        | Severity |
|--------|-----------------------------|----------|
| MCP001 | Plaintext secrets in env    | CRITICAL |
| MCP002 | Credentials in args         | CRITICAL |
| MCP003 | Wildcard autoApprove        | CRITICAL |
| MCP004 | Tool poisoning in desc      | HIGH     |
| MCP005 | Full-schema poisoning       | HIGH     |
| MCP006 | Broad filesystem access     | HIGH     |
| MCP007 | Unverified npx packages     | MEDIUM   |
| MCP008 | Missing HTTPS               | MEDIUM   |
| MCP009 | World-readable config file  | MEDIUM   |
| MCP010 | Unresolved env var refs     | LOW      |
| MCP011 | Known vulnerable packages   | HIGH     |
| MCP012 | Rug pull detection          | MEDIUM   |

## MCP config auto-discovery paths
| Client             | Path                                                                 |
|--------------------|----------------------------------------------------------------------|
| Claude Desktop Mac | ~/Library/Application Support/Claude/claude_desktop_config.json     |
| Claude Desktop Win | %APPDATA%/Claude/claude_desktop_config.json                         |
| Claude Code        | .mcp.json (cwd), ~/.claude.json                                      |
| Cursor             | ~/.cursor/mcp.json                                                   |
| VS Code            | .vscode/mcp.json                                                     |

## MCP config JSON format
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
      "env": { "API_KEY": "sk-abc123" },
      "autoApprove": ["read_file"]
    }
  }
}
```

## Secret patterns for MCP001
- GitHub PAT:        ghp_[A-Za-z0-9]{36}
- OpenAI key:        sk-[A-Za-z0-9]{48}
- AWS access key:    AKIA[0-9A-Z]{16}
- JWT:               eyJhbGci[A-Za-z0-9._-]+
- Supabase key:      sbp_[a-f0-9]{40}
- High entropy:      >4.5 Shannon entropy, >20 chars, not ${VAR} pattern
- Generic:           (password|secret|token)=(?!\$\{)[^\s]{8,}

## Tool poisoning patterns for MCP004
- HTML tags:         <IMPORTANT>, <s>, <HIDDEN>, <INSTRUCTION>
- Exfil + path:      (read|send|access|copy).*(\.ssh|\.aws|\.env|mcp\.json)
- Cross-tool:        when (tool|function) .* is called
- Zero-width:        \u200b \u200c \u200d \ufeff
- Social eng:        "do not tell the user", "required for authentication"
- Base64 payload:    [A-Za-z0-9+/]{40,}={0,2} in description fields

## Known CVEs for MCP011 (src/mcp_audit/data/cve_list.json)
- mcp-remote:                      CVE-2025-6514   CRITICAL  command injection
- @modelcontextprotocol/inspector:  CVE-2025-49596  CRITICAL  RCE dns rebinding
- framelink-figma-mcp:             CVE-2025-53967  HIGH      command injection
- mcp-server-git:                  CVE-2025-68143  CRITICAL  RCE chain
- gemini-mcp-tool:                 CVE-2026-0755   CRITICAL  unsanitized exec

## SARIF 2.1.0 structure
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "mcp-audit",
        "rules": [{ "id": "MCP001", "name": "...", "shortDescription": {...}, "helpUri": "..." }]
      }
    },
    "results": [{
      "ruleId": "MCP001",
      "level": "error",
      "message": { "text": "..." },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "file:///path/to/mcp.json" } } }]
    }]
  }]
}
```
Severity mapping: error=CRITICAL/HIGH, warning=MEDIUM, note=LOW

## Output severity colors (Rich)
CRITICAL → red bold
HIGH     → red
MEDIUM   → yellow
LOW      → blue
INFO     → white

## Baseline file for MCP012
~/.mcp-audit/baselines.json
Format: { "server_name": { "tool_name": "sha256_hash_of_definition" } }

## Code style
- Type hints everywhere, no Any unless truly unavoidable
- Docstrings on all public classes and methods
- Tests required for every check (min 3 cases: pass, fail, edge)
- ruff for linting, mypy strict mode
- Use platformdirs for all cross-platform path resolution
