"""Consent and authorization gates.

Two separate concepts, deliberately kept apart:

* **Terms** - the legal notice that collection only uses public/authorized
  sources. Accepted once, persisted, or forced with ``--accept-terms`` /
  ``REAPER_ACCEPT_TERMS=1``. Never blocks silently under a pipe.
* **Authorization** - per-run confirmation that the operator may actively test
  *this specific target*. Required for port scanning, subdomain brute force and
  web vulnerability probing. Passive/public lookups do not need it.

Both gates are non-interactive-safe: with no tty they return a machine readable
refusal instead of calling ``input()`` and hanging forever.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

from . import ui
from .config import Config
from .utils import env_flag

NOTICE = """
KING REAPER X - AUTHORIZED SECURITY TESTING ONLY

This framework collects data exclusively from:
  * public registries and public DNS / WHOIS data
  * public certificate transparency logs
  * official provider APIs you supply a key for
  * targets for which you confirm you own or hold written permission

It does NOT and will never: track a person's phone location, read WhatsApp
messages, intercept OTP codes, bypass account authentication, or access any
device without the owner's explicit consent.

Active modules (port scan, subdomain brute force, web probing) require an
explicit authorization confirmation per run.
""".strip()


def terms_accepted(config: Config) -> bool:
    if str(os.environ.get("REAPER_ACCEPT_TERMS", "")).strip().lower() in ("1", "true", "yes", "on"):
        return True
    return config.get_bool("consent_accepted", False)


def is_interactive() -> bool:
    """True only when a human can actually answer a prompt.

    ``REAPER_NONINTERACTIVE=1`` forces the non-interactive path. That matters
    because tmux, CI runners and ``script`` sessions all hand us a real tty with
    nobody on the other end - prompting there blocks the run forever instead of
    failing cleanly.
    """
    if env_flag("REAPER_NONINTERACTIVE"):
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def request_terms(
    config: Config,
    interactive: Optional[bool] = None,
    force_accept: bool = False,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Return ``{ok, accepted, reason}``.

    ``ok`` mirrors ``accepted`` so callers can branch once. Never raises and
    never blocks when there is no tty.
    """
    if force_accept:
        _persist(config)
        return {"ok": True, "accepted": True, "reason": "flag"}
    if terms_accepted(config):
        return {"ok": True, "accepted": True, "reason": "remembered"}

    if interactive is None:
        interactive = is_interactive()
    if not interactive:
        return {
            "ok": False,
            "accepted": False,
            "reason": "non_interactive",
            "error": "terms_not_accepted",
            "message": (
                "Terms not accepted and no terminal available. Re-run with "
                "--accept-terms or set REAPER_ACCEPT_TERMS=1."
            ),
        }

    if not quiet:
        print(ui.c(NOTICE, ui.GREY))
        print()
    try:
        answer = input(ui.c("  Accept and continue? [y/N] ", ui.BLOOD + ui.BOLD)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return {"ok": False, "accepted": False, "reason": "declined", "error": "terms_not_accepted"}
    if answer not in ("y", "yes"):
        return {"ok": False, "accepted": False, "reason": "declined", "error": "terms_not_accepted"}
    _persist(config)
    return {"ok": True, "accepted": True, "reason": "prompt"}


def _persist(config: Config) -> None:
    config.set("consent_accepted", True)
    try:
        config.save()
    except OSError:
        pass


def require_terms(config: Config, args: Any = None) -> Optional[Dict[str, Any]]:
    """Gate used by the CLI. Returns a failure envelope or ``None`` when fine."""
    force = bool(getattr(args, "accept_terms", False)) if args is not None else False
    quiet = bool(getattr(args, "quiet", False)) if args is not None else False
    outcome = request_terms(config, force_accept=force, quiet=quiet)
    if outcome["accepted"]:
        return None
    return {
        "ok": False,
        "error": "terms_not_accepted",
        "message": outcome.get("message", "Terms not accepted."),
        "hint": "--accept-terms",
    }


ACTIVE_MODULES = {
    "ports": "Port scanning sends packets to the target host",
    "subdomains": "Subdomain enumeration may include DNS brute force",
    "webscan": "Web assessment sends requests that probe for misconfigurations",
    "ports_scan": "Port scanning sends packets to the target host",
    "vuln": "Vulnerability checks actively probe the target",
}


def require_authorization(target: str, authorized: bool, module: str = "") -> Optional[Dict[str, Any]]:
    """Gate for active testing. Returns a refusal envelope or ``None``."""
    if authorized:
        return None
    why = ACTIVE_MODULES.get(module, "This module actively tests the target")
    return {
        "ok": False,
        "error": "authorization_required",
        "message": (
            f"{why}. Confirm you own '{target}' or hold written permission by "
            "re-running with --authorized."
        ),
        "target": target,
        "module": module,
        "hint": "--authorized",
    }
