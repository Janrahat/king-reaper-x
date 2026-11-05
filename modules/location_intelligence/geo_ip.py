"""IP geolocation and network ownership — public, keyless by default.

Uses only public geolocation services that answer without a key, and never claims
GPS-level accuracy: an IP locates a network edge, not a person, and the result is
labelled as such. Higher accuracy is available by supplying an ipinfo token.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from core.config import PROVIDERS, Config
from core.errors import NetworkError
from core.providers import api_get, degraded
from core.utils import is_ip, is_private_ip, now_iso, resolve_host

NAME = "geoip"
TITLE = "IP Geolocation"
DESCRIPTION = "Approximate country/region/city for a public IP or hostname, plus ASN and reverse DNS"
CATEGORY = "location"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

ACCURACY_NOTE = (
    "IP geolocation resolves the registered network block, not the device. City-level "
    "results are typically accurate to 10-100 km and must never be treated as a "
    "person's location."
)


def _free_lookup(ip: str, timeout: float = 10.0) -> Dict[str, Any]:
    """ip-api.com free endpoint — no key, 45 requests/minute."""
    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,continent,country,countryCode,regionName,city,"
        "district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    response = api_get(url, timeout=timeout)
    if not response["ok"]:
        return {"ok": False, "error": response.get("error") or "provider_error",
                "status": response.get("status"), "provider": "ip-api"}
    data = response.get("data") or {}
    if not isinstance(data, dict) or data.get("status") != "success":
        return {
            "ok": False,
            "error": str(data.get("message") or "lookup_failed").lower().replace(" ", "_"),
            "provider": "ip-api",
            "message": data.get("message") or "ip-api returned no data",
        }
    return {
        "ok": True,
        "provider": "ip-api",
        "ip": data.get("query"),
        "continent": data.get("continent"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "district": data.get("district"),
        "postal": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as") or data.get("asname"),
        "reverse_dns": data.get("reverse"),
        "mobile": data.get("mobile"),
        "proxy_or_vpn": data.get("proxy"),
        "hosting": data.get("hosting"),
    }


def _ipinfo_lookup(ip: str, token: str, timeout: float = 10.0) -> Dict[str, Any]:
    response = api_get(f"https://ipinfo.io/{ip}/json?token={token}", timeout=timeout)
    if not response["ok"]:
        return {"ok": False, "error": response.get("error") or "provider_error",
                "status": response.get("status"), "provider": "ipinfo"}
    data = response.get("data") or {}
    if not isinstance(data, dict):
        return {"ok": False, "error": "bad_provider_payload", "provider": "ipinfo"}
    lat, lon = None, None
    loc = str(data.get("loc") or "")
    if "," in loc:
        try:
            lat_s, lon_s = loc.split(",", 1)
            lat, lon = float(lat_s), float(lon_s)
        except ValueError:
            lat, lon = None, None
    return {
        "ok": True,
        "provider": "ipinfo",
        "ip": data.get("ip"),
        "country": (data.get("country") or "").upper() or None,
        "country_code": (data.get("country") or "").upper() or None,
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": lat,
        "longitude": lon,
        "timezone": data.get("timezone"),
        "org": data.get("org"),
        "asn": data.get("org"),
        "hostname": data.get("hostname"),
    }


def locate(target: str, config: Optional[Config] = None, timeout: float = 10.0) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": target,
        "queried_at": now_iso(),
        "findings": [],
        "accuracy_note": ACCURACY_NOTE,
    }

    ip = (target or "").strip()
    resolved_from: Optional[str] = None
    if not is_ip(ip):
        addresses = resolve_host(ip, timeout=5.0)
        if not addresses:
            result.update(
                {
                    "error": "unresolvable",
                    "message": f"'{target}' is neither a valid IP nor a resolvable hostname.",
                }
            )
            return result
        resolved_from = ip
        ip = addresses[0]

    result["ip"] = ip
    result["resolved_from"] = resolved_from

    if is_private_ip(ip):
        result.update(
            {
                "ok": True,
                "private": True,
                "geo": {},
                "summary": f"{ip} is in a private/reserved range — no public geolocation exists.",
                "message": (
                    "Private addresses are never geolocatable; they only exist inside "
                    "their own network."
                ),
            }
        )
        return result

    token = config.api_key("ipinfo")
    geo: Dict[str, Any]
    if token:
        geo = _ipinfo_lookup(ip, token, timeout)
        if not geo.get("ok"):
            geo = _free_lookup(ip, timeout)
    else:
        geo = _free_lookup(ip, timeout)

    if not geo.get("ok"):
        result.update(
            {
                "error": geo.get("error") or "lookup_failed",
                "message": geo.get("message") or "No geolocation provider returned data.",
                "degraded": True,
                "provider": geo.get("provider"),
            }
        )
        return result

    result["ok"] = True
    result["geo"] = {
        key: value
        for key, value in geo.items()
        if key not in ("ok", "provider") and value not in (None, "")
    }
    result["provider"] = geo.get("provider")
    maps_lat, maps_lon = geo.get("latitude"), geo.get("longitude")
    if maps_lat is not None and maps_lon is not None:
        result["map"] = {
            "latitude": maps_lat,
            "longitude": maps_lon,
            "osm_url": f"https://www.openstreetmap.org/?mlat={maps_lat}&mlon={maps_lon}#map=11/{maps_lat}/{maps_lon}",
            "static_preview_note": "Open the OSM URL to visualise; no tiles are embedded to avoid third-party calls.",
        }

    city = geo.get("city") or "unknown city"
    country = geo.get("country") or geo.get("country_code") or "unknown country"
    result["summary"] = f"{ip} → {city}, {country} ({geo.get('org') or geo.get('isp') or 'unknown network'})"

    if geo.get("proxy_or_vpn"):
        result["findings"].append(
            {
                "severity": "info",
                "title": "Anonymising network detected",
                "detail": "The provider flags this address as a proxy/VPN exit. Geolocation may reflect the exit node, not the user.",
            }
        )
    if geo.get("hosting"):
        result["findings"].append(
            {
                "severity": "info",
                "title": "Datacenter / hosting address",
                "detail": "Traffic from this address likely originates from a server rather than a residential connection.",
            }
        )
    result["risk"] = "info"
    result["score"] = 0
    return result


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return locate(target, config=config, timeout=float(options.get("timeout", 10.0)))


def provider_status(config: Optional[Config] = None) -> Dict[str, Any]:
    """Report which geolocation sources are usable right now."""
    config = config or Config()
    spec = PROVIDERS["ipinfo"]
    if config.api_key("ipinfo"):
        return {"provider": "ipinfo", "configured": True, "accuracy": "high"}
    return degraded(
        "ipinfo",
        spec.env_var,
        "Higher-accuracy IP geolocation",
        fallback="ip-api.com (keyless, city-level)",
        accuracy="city-level",
    )
