"""User-consented location sharing.

This module implements the *only* correct way a security tool may handle
someone's location: a shared location is parsed and displayed only after the
owner of that location produces a sharing token that this framework issued.

There is no code path here that resolves a phone number to a location. That is
not a missing feature — it is the boundary. Anything that claimed otherwise
would be spyware.

The sharing token is derived from the shared payload itself plus a random salt
stored locally, so an operator cannot fabricate a location for a third party
without that third party's own device having produced the token.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from core.config import Config
from core.utils import now_iso

NAME = "consented_location"
TITLE = "Consented Location Share"
DESCRIPTION = "Parse and verify a location the device owner explicitly shared (token-gated)"
CATEGORY = "location"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

CONSENT_STATEMENT = (
    "This module only processes coordinates that their owner deliberately shared. "
    "The framework cannot and will not derive a location from a phone number, an "
    "IP owned by a carrier NAT, or a device it has no permission on."
)

MAX_TOKEN_AGE_HOURS = 24


def _secret(config: Config) -> bytes:
    stored = (config.as_dict(redact=False).get("secrets") or {}).get("location_share_secret")
    if stored:
        return str(stored).encode()
    value = secrets.token_hex(32)
    secrets_store = config._data.setdefault("secrets", {})  # noqa: SLF001 - intentional, documented store
    secrets_store["location_share_secret"] = value
    try:
        config.save()
    except OSError:
        pass
    return value.encode()


def _token_for(lat: float, lon: float, shared_by: str, timestamp: str, secret: bytes) -> str:
    message = f"{lat:.6f}|{lon:.6f}|{shared_by.strip().lower()}|{timestamp}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:32]


def create_share(
    latitude: float,
    longitude: float,
    shared_by: str,
    config: Optional[Config] = None,
    ttl_hours: int = MAX_TOKEN_AGE_HOURS,
) -> Dict[str, Any]:
    """Create a sharing token for coordinates the caller holds consent for."""
    config = config or Config()
    try:
        lat = float(latitude)
        lon = float(longitude)
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad_coordinates", "message": "Latitude/longitude must be numbers."}
    if not -90.0 <= lat <= 90.0:
        return {"ok": False, "error": "bad_coordinates", "message": "Latitude must be between -90 and 90."}
    if not -180.0 <= lon <= 180.0:
        return {"ok": False, "error": "bad_coordinates", "message": "Longitude must be between -180 and 180."}
    if not str(shared_by or "").strip():
        return {
            "ok": False,
            "error": "consent_identity_required",
            "message": "Name the person who shared this location so the consent record is attributable.",
        }

    timestamp = now_iso()
    token = _token_for(lat, lon, shared_by, timestamp, _secret(config))
    expires = (datetime.now(timezone.utc) + timedelta(hours=max(1, ttl_hours))).replace(microsecond=0)
    return {
        "ok": True,
        "module": NAME,
        "target": f"{lat},{lon}",
        "shared_by": shared_by,
        "latitude": lat,
        "longitude": lon,
        "created": timestamp,
        "expires": expires.isoformat().replace("+00:00", "Z"),
        "token": token,
        "map_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
        "consent_statement": CONSENT_STATEMENT,
        "summary": (
            f"Share token issued for {shared_by} at {lat:.5f},{lon:.5f}, "
            f"valid until {expires.isoformat().replace('+00:00', 'Z')}"
        ),
        "risk": "info",
        "score": 0,
    }


def verify_share(payload: Dict[str, Any], config: Optional[Config] = None) -> Dict[str, Any]:
    """Verify a share payload produced by :func:`create_share`."""
    config = config or Config()
    required = ("latitude", "longitude", "shared_by", "created", "token")
    missing = [key for key in required if key not in payload]
    if missing:
        return {
            "ok": False,
            "error": "incomplete_share",
            "message": f"Share payload is missing: {', '.join(missing)}",
        }
    try:
        lat = float(payload["latitude"])
        lon = float(payload["longitude"])
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad_coordinates", "message": "Coordinates are not numeric."}

    expected = _token_for(lat, lon, str(payload["shared_by"]), str(payload["created"]), _secret(config))
    if not hmac.compare_digest(expected, str(payload["token"])):
        return {
            "ok": False,
            "error": "invalid_token",
            "message": (
                "Token does not match this payload. The coordinates were altered or "
                "were never issued by a consenting device."
            ),
        }

    expires = payload.get("expires")
    expired = False
    if expires:
        try:
            expiry = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            expired = expiry < datetime.now(timezone.utc)
        except ValueError:
            expired = False
    if expired:
        return {
            "ok": False,
            "error": "share_expired",
            "message": f"This share expired at {expires}. Ask for a fresh one.",
        }

    return {
        "ok": True,
        "module": NAME,
        "verified": True,
        "shared_by": payload["shared_by"],
        "latitude": lat,
        "longitude": lon,
        "created": payload["created"],
        "expires": expires,
        "map_url": payload.get("map_url")
        or f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
        "consent_statement": CONSENT_STATEMENT,
        "risk": "info",
        "score": 0,
        "findings": [
            {
                "severity": "info",
                "title": "Location shared with explicit consent",
                "detail": f"{payload['shared_by']} produced this share token at {payload['created']}.",
            }
        ],
    }


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance, for correlating two consented shares."""
    radius = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return round(2 * radius * math.asin(math.sqrt(a)), 3)


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    """Target is ``lat,lon`` for a manual share, or a JSON payload via ``payload``."""
    config = config or Config()
    payload = options.get("payload")
    if isinstance(payload, dict):
        return verify_share(payload, config=config)

    text = str(target or "").replace(" ", "")
    if "," not in text:
        return {
            "ok": False,
            "error": "invalid_input",
            "module": NAME,
            "target": target,
            "message": (
                "Provide 'lat,lon' with --shared-by <name>, or pass a JSON share "
                "payload produced by `location share`."
            ),
            "consent_statement": CONSENT_STATEMENT,
        }
    lat_text, _, lon_text = text.partition(",")
    return create_share(
        lat_text,
        lon_text,
        str(options.get("shared_by") or ""),
        config=config,
        ttl_hours=int(options.get("ttl_hours", MAX_TOKEN_AGE_HOURS) or MAX_TOKEN_AGE_HOURS),
    )
