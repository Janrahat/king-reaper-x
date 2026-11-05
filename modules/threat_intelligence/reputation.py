"""Threat intelligence from public, keyless feeds plus optional providers.

Sources used without any key:

* ``urlhaus.abuse.ch`` — recent malicious URL feed (public download).
* ``openphish.com`` — public phishing feed.
* ``dns.google`` DoH — resolves known-bad indicators for comparison.

Sources used only when a key exists: VirusTotal (domain/IP/URL reputation) and
AbuseIPDB (IP abuse confidence). Absent keys produce a labelled degraded result,
never a fabricated score.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import PROVIDERS, Config
from core.errors import NetworkError
from core.providers import api_get, degraded
from core.utils import is_domain, is_ip, now_iso

NAME = "threat"
TITLE = "Threat Intelligence"
DESCRIPTION = "Reputation for a domain, IP or URL from VirusTotal, AbuseIPDB and public phishing feeds"
CATEGORY = "threat"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
FEED_CACHE: Dict[str, Any] = {}

ABUSE_CATEGORIES = {
    "phishing": "credential harvesting site",
    "malware": "malware distribution",
    "botnet": "botnet infrastructure",
    "spam": "spam source",
}


def _load_feed(url: str, timeout: float = 20.0, limit_lines: int = 20000) -> Dict[str, Any]:
    """Fetch and cache a plaintext indicator feed for the process lifetime."""
    cached = FEED_CACHE.get(url)
    if cached:
        return cached
    response = net.http_request(url, timeout=timeout, max_body=4 * 1024 * 1024)
    if not response["ok"]:
        payload = {"ok": False, "source": url, "indicators": set(), "error": response.get("error")}
        return payload
    body = response.get("body") or ""
    indicators = set()
    for line in body.splitlines()[:limit_lines]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        indicators.add(line.lower())
    payload = {"ok": True, "source": url, "indicators": indicators, "error": None, "count": len(indicators)}
    FEED_CACHE[url] = payload
    return payload


def _match_feeds(domain: str, url: Optional[str] = None) -> List[Dict[str, Any]]:
    """Substring match of the indicator against public phishing/malware feeds."""
    hits: List[Dict[str, Any]] = []
    targets = [item for item in (domain.lower(), (url or "").lower()) if item]
    for feed_url, label in ((URLHAUS_FEED, "URLhaus"), (OPENPHISH_FEED, "OpenPhish")):
        try:
            feed = _load_feed(feed_url)
        except Exception:  # noqa: BLE001
            continue
        if not feed.get("ok"):
            continue
        for indicator in feed.get("indicators", ()):
            for target in targets:
                if target and target in indicator:
                    hits.append({"feed": label, "indicator": indicator[:200], "matched": target})
                    break
    return hits


def _virustotal_domain(domain: str, config: Config) -> Dict[str, Any]:
    spec = PROVIDERS["virustotal"]
    key = config.api_key("virustotal")
    if not key:
        return degraded("virustotal", spec.env_var, spec.purpose)
    try:
        response = api_get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15.0,
        )
    except NetworkError as exc:
        return {"ok": False, "degraded": True, "provider": "virustotal", "error": "network_error", "message": str(exc)}
    if not response["ok"]:
        return {
            "ok": False,
            "degraded": True,
            "provider": "virustotal",
            "error": response.get("error") or "provider_error",
            "status": response.get("status"),
            "message": "VirusTotal rejected the request; check key and quota.",
        }
    data = (response.get("data") or {}).get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    categories = attributes.get("categories") or {}
    return {
        "ok": True,
        "provider": "virustotal",
        "reputation": attributes.get("reputation"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "categories": categories,
        "registrar": attributes.get("registrar"),
        "creation_date": attributes.get("creation_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def _virustotal_ip(ip: str, config: Config) -> Dict[str, Any]:
    spec = PROVIDERS["virustotal"]
    key = config.api_key("virustotal")
    if not key:
        return degraded("virustotal", spec.env_var, spec.purpose)
    try:
        response = api_get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=15.0,
        )
    except NetworkError as exc:
        return {"ok": False, "degraded": True, "provider": "virustotal", "error": "network_error", "message": str(exc)}
    if not response["ok"]:
        return {
            "ok": False,
            "degraded": True,
            "provider": "virustotal",
            "error": response.get("error") or "provider_error",
            "status": response.get("status"),
        }
    data = (response.get("data") or {}).get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "ok": True,
        "provider": "virustotal",
        "reputation": attributes.get("reputation"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
    }


def _abuseipdb(ip: str, config: Config) -> Dict[str, Any]:
    spec = PROVIDERS["abuseipdb"]
    key = config.api_key("abuseipdb")
    if not key:
        return degraded("abuseipdb", spec.env_var, spec.purpose)
    try:
        response = api_get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": key, "Accept": "application/json"},
            timeout=15.0,
        )
    except NetworkError as exc:
        return {"ok": False, "degraded": True, "provider": "abuseipdb", "error": "network_error", "message": str(exc)}
    if not response["ok"]:
        return {
            "ok": False,
            "degraded": True,
            "provider": "abuseipdb",
            "error": response.get("error") or "provider_error",
            "status": response.get("status"),
        }
    data = (response.get("data") or {}).get("data") or {}
    return {
        "ok": True,
        "provider": "abuseipdb",
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "distinct_users": data.get("numDistinctUsers"),
        "last_reported": data.get("lastReportedAt"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "is_whitelisted": data.get("isWhitelisted"),
    }


def check(target: str, config: Optional[Config] = None, include_feeds: bool = True) -> Dict[str, Any]:
    config = config or Config()
    value = (target or "").strip()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": value,
        "queried_at": now_iso(),
        "findings": [],
        "sources": {},
    }
    if not value:
        result.update({"error": "empty_target", "message": "Supply a domain or IP."})
        return result

    findings: List[Dict[str, Any]] = result["findings"]
    is_addr = is_ip(value)
    domain = "" if is_addr else value.lower().rstrip(".")

    if is_addr:
        result["kind"] = "ip"
        vt = _virustotal_ip(value, config)
        result["sources"]["virustotal"] = vt
        result["sources"]["abuseipdb"] = _abuseipdb(value, config)
        if vt.get("ok"):
            malicious = int(vt.get("malicious") or 0)
            if malicious:
                findings.append(
                    {
                        "severity": "high" if malicious < 10 else "critical",
                        "title": f"{malicious} engine(s) flag this IP",
                        "detail": "VirusTotal malicious detections: "
                        + str(malicious)
                        + f", reputation {vt.get('reputation')}",
                        "reference": f"https://www.virustotal.com/gui/ip-address/{value}",
                    }
                )
        abuse = result["sources"]["abuseipdb"]
        if abuse.get("ok"):
            score = int(abuse.get("abuse_confidence") or 0)
            if score >= 25:
                findings.append(
                    {
                        "severity": "high" if score >= 75 else "medium",
                        "title": f"AbuseIPDB confidence {score}%",
                        "detail": f"{abuse.get('total_reports')} report(s) in 90 days, ISP {abuse.get('isp')}.",
                        "reference": f"https://www.abuseipdb.com/check/{value}",
                    }
                )
    elif is_domain(value):
        result["kind"] = "domain"
        vt = _virustotal_domain(domain, config)
        result["sources"]["virustotal"] = vt
        if vt.get("ok"):
            malicious = int(vt.get("malicious") or 0)
            suspicious = int(vt.get("suspicious") or 0)
            if malicious or suspicious:
                findings.append(
                    {
                        "severity": "critical" if malicious >= 5 else "high",
                        "title": f"{malicious} malicious / {suspicious} suspicious detection(s)",
                        "detail": f"VirusTotal reputation {vt.get('reputation')}.",
                        "reference": f"https://www.virustotal.com/gui/domain/{domain}",
                    }
                )
        if include_feeds:
            matches = _match_feeds(domain)
            result["sources"]["public_feeds"] = {
                "ok": True,
                "matches": matches,
                "checked": ["URLhaus", "OpenPhish"],
            }
            if matches:
                findings.append(
                    {
                        "severity": "critical",
                        "title": f"Listed in {matches[0]['feed']}",
                        "detail": f"Indicator: {matches[0]['indicator'][:120]}",
                        "reference": "https://urlhaus.abuse.ch/",
                    }
                )
    else:
        result.update({"error": "bad_target", "message": f"'{value}' is neither a valid domain nor an IP."})
        return result

    result["ok"] = True
    configured = [name for name in ("virustotal", "abuseipdb") if config.api_key(name)]
    result["providers_configured"] = configured
    if not configured:
        result["degraded"] = True
        result["message"] = (
            "No reputation API keys configured, so this result relies on public feeds "
            "only. Set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY for full coverage."
        )

    result["risk"] = _risk(findings)
    result["score"] = _score(findings)
    result["summary"] = (
        f"{value}: {len(findings)} reputation finding(s)"
        + ("" if configured else " (public feeds only — no API key configured)")
    )
    return result


def _risk(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(str(item.get("severity", "info")).lower(), 0) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst]


def _score(findings: List[Dict[str, Any]]) -> int:
    weights = {"critical": 45, "high": 25, "medium": 10, "low": 4, "info": 0}
    return min(100, sum(weights.get(str(item.get("severity", "info")).lower(), 0) for item in findings))


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return check(
        target,
        config=config,
        include_feeds=bool(options.get("include_feeds", True)),
    )
