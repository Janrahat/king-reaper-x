"""Thin, auditable HTTP helper for the optional provider APIs.

All provider modules go through :func:`api_get` so that credential handling,
timeouts, rate limiting and error mapping exist in exactly one place. A missing
key raises :class:`ProviderNotConfigured`, which the caller converts into a
graceful "degraded" result.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Mapping, Optional

from .config import PROVIDERS, Config
from .errors import NetworkError, ProviderNotConfigured
from .logging_setup import get_logger

logger = get_logger("providers")

DEFAULT_TIMEOUT = 12.0


def require_key(config: Config, provider: str) -> str:
    key = config.api_key(provider)
    if not key:
        spec = PROVIDERS.get(provider)
        env_var = spec.env_var if spec else f"{provider.upper()}_API_KEY"
        purpose = spec.purpose if spec else ""
        raise ProviderNotConfigured(provider, env_var, purpose)
    return key


def build_url(base: str, params: Optional[Mapping[str, Any]] = None) -> str:
    if not params:
        return base
    filtered = {key: value for key, value in params.items() if value is not None}
    if not filtered:
        return base
    joiner = "&" if "?" in base else "?"
    return f"{base}{joiner}{urllib.parse.urlencode(filtered)}"


def api_get(
    url: str,
    headers: Optional[Mapping[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    expect_json: bool = True,
) -> Dict[str, Any]:
    """GET *url* and return ``{ok, status, data, text, error, elapsed_ms}``.

    Raises :class:`NetworkError` only for transport failures; HTTP error codes are
    returned as data so the caller can interpret 404 vs 429 vs 401 precisely.
    """
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", "KING-REAPER-X/1.0 security-assessment")
    request.add_header("Accept", "application/json" if expect_json else "*/*")
    for key, value in (headers or {}).items():
        if value:
            request.add_header(key, str(value))

    start = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(1024 * 1024)
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        raw = exc.read(64 * 1024) if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", "replace")
        return {
            "ok": False,
            "status": getattr(exc, "code", None),
            "data": _try_json(text),
            "text": text,
            "error": _http_reason(getattr(exc, "code", None)),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"{type(exc).__name__}: {exc}", url=url) from exc

    text = raw.decode("utf-8", "replace")
    return {
        "ok": 200 <= status < 300,
        "status": status,
        "data": _try_json(text) if expect_json else None,
        "text": text if not expect_json else "",
        "error": None,
        "elapsed_ms": int((time.time() - start) * 1000),
    }


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _http_reason(status: Optional[int]) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden_or_quota",
        404: "not_found",
        429: "rate_limited",
        500: "provider_error",
        502: "provider_error",
        503: "provider_unavailable",
    }.get(status, f"http_{status}")


def degraded(provider: str, env_var: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    """Standard payload for an unconfigured optional provider."""
    payload: Dict[str, Any] = {
        "ok": True,
        "degraded": True,
        "provider": provider,
        "requires": env_var,
        "message": (
            f"{purpose or 'This enrichment'} needs {env_var}. "
            f"Set it to enable this section; everything else still works."
        ),
        "hint": f"export {env_var}=<key>",
    }
    payload.update(extra)
    return payload
