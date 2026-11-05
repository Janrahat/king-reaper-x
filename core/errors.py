"""Typed errors shared by every KING REAPER X module.

Modules never raise for expected conditions (missing API key, target offline,
provider rate limit). They return ``{"ok": False, "error": <code>, ...}`` so the
CLI, the dashboard and the tests can all branch on the same machine readable
token instead of parsing prose.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ReaperError(Exception):
    """Base class for framework errors."""

    code = "reaper_error"

    def __init__(self, message: str, code: Optional[str] = None, **detail: Any) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.detail: Dict[str, Any] = detail

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"ok": False, "error": self.code, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class ConfigError(ReaperError):
    code = "config_error"


class ValidationError(ReaperError):
    code = "validation_error"


class NetworkError(ReaperError):
    code = "network_error"


class ProviderNotConfigured(ReaperError):
    """Raised (or returned) when an optional data provider has no credential.

    This is *not* a bug: the module degrades gracefully and tells the operator
    exactly which key to set and where.
    """

    code = "provider_not_configured"

    def __init__(self, provider: str, env_var: str, purpose: str = "") -> None:
        message = (
            f"Provider '{provider}' is not configured. "
            f"Set {env_var} in the environment (preferred) or run "
            f"`python main.py config set-key {provider} <KEY>`."
        )
        super().__init__(message, provider=provider, env_var=env_var, purpose=purpose)
        self.provider = provider
        self.env_var = env_var
        self.purpose = purpose

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": self.code,
            "message": self.message,
            "provider": self.provider,
            "requires": self.env_var,
            "purpose": self.purpose,
            "hint": f"export {self.env_var}=<your-key>",
        }


class AuthorizationRequired(ReaperError):
    """Raised before active testing on a target the operator has not proven
    they are allowed to test."""

    code = "authorization_required"

    def __init__(self, target: str, reason: str = "") -> None:
        message = (
            f"Active testing of '{target}' requires an explicit authorization "
            "confirmation. Re-run with --authorized (CLI) after confirming you "
            "own the target or hold written permission."
        )
        if reason:
            message = f"{message} {reason}"
        super().__init__(message, target=target)


def fail(code: str, message: str, **detail: Any) -> Dict[str, Any]:
    """Build the standard failure envelope."""
    payload: Dict[str, Any] = {"ok": False, "error": code, "message": message}
    if detail:
        payload.update(detail)
    return payload


def ok(**payload: Any) -> Dict[str, Any]:
    """Build the standard success envelope."""
    result: Dict[str, Any] = {"ok": True}
    result.update(payload)
    return result
