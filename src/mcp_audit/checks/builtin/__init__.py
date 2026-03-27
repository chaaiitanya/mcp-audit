"""Auto-import all builtin checks to trigger @register_check decorators."""

from mcp_audit.checks.builtin import (  # noqa: F401
    mcp001_plaintext_secrets,
    mcp002_credentials_in_args,
    mcp003_wildcard_approve,
    mcp004_tool_poisoning,
    mcp005_full_schema_poisoning,
    mcp006_filesystem_scope,
    mcp007_unverified_npm,
    mcp008_missing_https,
    mcp009_file_permissions,
    mcp010_unresolved_env_vars,
    mcp011_known_cves,
    mcp012_rug_pull,
)
