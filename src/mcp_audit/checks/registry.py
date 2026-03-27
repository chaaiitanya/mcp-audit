"""Check registry with auto-registration decorator."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.checks.base import BaseCheck

_REGISTRY: dict[str, type[BaseCheck]] = {}


def register_check(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Decorator that registers a check class by its check_id."""
    _REGISTRY[cls.check_id] = cls
    return cls


def get_all_checks() -> list[BaseCheck]:
    """Import all builtin checks and return instantiated instances."""
    import mcp_audit.checks.builtin  # noqa: F401 — side-effect import

    return [cls() for cls in _REGISTRY.values()]


def get_registry() -> dict[str, type[BaseCheck]]:
    """Return the raw registry dict for inspection."""
    return _REGISTRY
