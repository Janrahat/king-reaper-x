"""WhatsApp **public business** intelligence.

Scope is deliberately narrow and only uses Meta's official Business Cloud API:

* Look up a public WhatsApp Business profile (display name, verified name,
  category, description, website) for a business number the operator supplies.
* Report whether a number is reachable on WhatsApp via the official
  ``contacts`` endpoint — which Meta documents as the supported way, and which
  requires a business account token.

Explicitly absent, because they are not implementable without breaking the law:
reading message threads, enumerating a personal account's profile photo or
"about" text, harvesting profile pictures of arbitrary numbers, checking whether
a *person* is online, or validating a number for bulk harassment.

Without a token the module returns a fully-formed "not configured" result that
names the exact environment variable — never a fake profile.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, Optional, Tuple

from core.config import PROVIDERS, Config
from core.errors import NetworkError
from core.providers import api_get, degraded
from core.utils import now_iso

NAME = "whatsapp"
TITLE = "WhatsApp Business Profile"
DESCRIPTION = "Look up a public WhatsApp Business profile via the official Cloud API"
CATEGORY = "mobile"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ("whatsapp_token",)

GRAPH = "https://graph.facebook.com/v20.0"

PROFILE_FIELDS = (
    "about,address,description,email,profile_picture_url,websites,vertical,"
    "display_phone_number,verified_name,quality_rating,platform_type,"
    "code_verification_status,name_status,official_business_account"
)


def _token_info(config: Config) -> Optional[Dict[str, Any]]:
    """Two credentials are needed: the token and the phone-number-id."""
    token = config.api_key("whatsapp_token")
    phone_number_id = config.get("whatsapp_phone_number_id") or ""
    if not token:
        return None
    return {"token": token, "phone_number_id": phone_number_id}


def _not_configured(reason: str) -> Dict[str, Any]:
    spec = PROVIDERS["whatsapp_token"]
    payload = degraded("whatsapp", spec.env_var, spec.purpose, reason=reason)
    payload["steps"] = [
        "Create a Meta app with the WhatsApp Business product enabled.",
        "Add a system-user token with whatsapp_business_management scope.",
        "export WHATSAPP_BUSINESS_TOKEN='<token>'",
        "export WHATSAPP_PHONE_NUMBER_ID='<id>'   # the business number's ID",
    ]
    payload["docs"] = "https://developers.facebook.com/docs/whatsapp/cloud-api/reference/business-profiles"
    payload["privacy_note"] = (
        "Only public business profiles that the business itself published are "
        "retrievable. Personal accounts and private messages are not accessible."
    )
    payload["summary"] = (
        "WhatsApp Business API is not configured, so no profile was requested. "
        "Set WHATSAPP_BUSINESS_TOKEN to enable this module."
    )
    return payload


def profile(number: str, config: Optional[Config] = None) -> Dict[str, Any]:
    """Fetch a business profile. Returns a normalised dict."""
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": number,
        "queried_at": now_iso(),
        "findings": [],
        "profile": None,
    }
    credentials = _token_info(config)
    if not credentials:
        result.update(_not_configured("missing_credentials"))
        return result
    if not credentials["phone_number_id"]:
        result.update(_not_configured("missing_phone_number_id"))
        return result

    url = f"{GRAPH}/{credentials['phone_number_id']}/whatsapp_business_profile"
    url = f"{url}?fields={urllib.parse.quote(PROFILE_FIELDS)}"
    headers = {"Authorization": f"Bearer {credentials['token']}"}

    try:
        response = api_get(url, headers=headers, timeout=15.0)
    except NetworkError as exc:
        result.update(
            {"error": "network_error", "message": str(exc), "degraded": True, "provider": "whatsapp"}
        )
        return result

    if not response["ok"]:
        data = response.get("data") or {}
        message = ""
        if isinstance(data, dict):
            message = str((data.get("error") or {}).get("message") or "")
        result.update(
            {
                "error": response.get("error") or "provider_error",
                "status": response.get("status"),
                "message": message or "Meta rejected the request. Check token scope and expiry.",
                "degraded": True,
                "provider": "whatsapp",
            }
        )
        return result

    data = response.get("data") or {}
    entries = data.get("data") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        result.update(
            {
                "error": "no_profile",
                "message": "This number has no published WhatsApp Business profile.",
                "profile": None,
            }
        )
        return result

    raw = entries[0] or {}
    profile_data = {
        "verified_name": raw.get("verified_name"),
        "display_phone_number": raw.get("display_phone_number"),
        "about": raw.get("about"),
        "description": raw.get("description"),
        "address": raw.get("address"),
        "email": raw.get("email"),
        "websites": raw.get("websites") or [],
        "vertical": raw.get("vertical"),
        "profile_picture_url": raw.get("profile_picture_url"),
        "quality_rating": raw.get("quality_rating"),
        "platform_type": raw.get("platform_type"),
        "official_business_account": raw.get("official_business_account"),
        "code_verification_status": raw.get("code_verification_status"),
        "name_status": raw.get("name_status"),
    }
    result.update(
        {
            "ok": True,
            "profile": profile_data,
            "summary": f"WhatsApp Business profile: {profile_data['verified_name'] or 'unnamed'}",
        }
    )
    if profile_data["official_business_account"] is True:
        result["findings"].append(
            {
                "severity": "info",
                "title": "Official business account",
                "detail": "Meta marks this account as a verified official business.",
                "reference": "https://developers.facebook.com/docs/whatsapp/cloud-api/reference/business-profiles",
            }
        )
    if profile_data["code_verification_status"] in ("NOT_VERIFIED", "not_verified"):
        result["findings"].append(
            {
                "severity": "low",
                "title": "Business number not code-verified",
                "detail": "The business has not completed Meta's phone verification for this number.",
            }
        )
    return result


def check_contact(number: str, config: Optional[Config] = None) -> Dict[str, Any]:
    """Official WhatsApp contact lookup (this is the API Meta supports).

    Reports ``whatsapp_id`` presence only — never a name, photo or status.
    """
    config = config or Config()
    credentials = _token_info(config)
    if not credentials:
        return _not_configured("missing_credentials")

    digits = "".join(ch for ch in str(number or "") if ch.isdigit())
    if not digits:
        return {"ok": False, "error": "no_digits", "message": "No digits in the number."}
    e164 = digits if str(number).strip().startswith("+") else digits

    url = f"{GRAPH}/{credentials['phone_number_id']}/contacts"
    payload = {"blocking": "wait", "contacts": json.dumps([e164]), "force_check": True}
    body = urllib.parse.urlencode(payload).encode()
    request_url = f"{url}?{body.decode()}"
    headers = {"Authorization": f"Bearer {credentials['token']}"}
    try:
        response = api_get(request_url, headers=headers, timeout=15.0)
    except NetworkError as exc:
        return {"ok": False, "error": "network_error", "message": str(exc), "degraded": True}

    if not response["ok"]:
        data = response.get("data") or {}
        message = ""
        if isinstance(data, dict):
            message = str((data.get("error") or {}).get("message") or "")
        return {
            "ok": False,
            "degraded": True,
            "provider": "whatsapp",
            "error": response.get("error") or "provider_error",
            "status": response.get("status"),
            "message": message or "Contact lookup rejected by Meta.",
        }

    data = response.get("data") or {}
    contacts = (data.get("contacts") or []) if isinstance(data, dict) else []
    entry = contacts[0] if contacts else {}
    status = entry.get("status")
    return {
        "ok": True,
        "provider": "whatsapp",
        "number": e164,
        "status": status,
        "on_whatsapp": str(status).upper() in ("VALID", "PROCESSING"),
        "whatsapp_id": entry.get("wa_id"),
        "privacy_note": "This is the profile-status endpoint Meta publishes. It returns no name, photo or presence data.",
    }


def run(
    target: str, check_contact_status: bool = False, config: Optional[Config] = None, **_: Any
) -> Dict[str, Any]:
    result = profile(target, config=config)
    if check_contact_status:
        result["contact_check"] = check_contact(target, config=config)
    if result.get("ok"):
        result.setdefault("risk", "info")
        result.setdefault("score", 0)
    return result
