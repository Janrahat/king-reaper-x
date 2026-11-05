"""Public username and email OSINT across sites that document a profile URL.

Design notes that matter:

* Every check is a single GET against the *public* profile URL. No login, no
  scraping behind auth, no rate-limit evasion.
* A hit requires the site's own "not found" signal to be absent **and** a
  positive marker present where one exists. Sites that answer 200 for everything
  are detected and reported as ``inconclusive`` rather than as a false positive.
* Emails are checked structurally and, when a HIBP key is supplied, against the
  official breach API. No email harvesting.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import PROVIDERS, Config
from core.logging_setup import get_logger
from core.providers import api_get
from core.utils import dedupe, is_email, is_username, now_iso, run_threaded

NAME = "username"
TITLE = "Username & Email OSINT"
DESCRIPTION = "Check public username availability across documented site profiles and validate email exposure"
CATEGORY = "osint"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

#: site -> (url template, positive marker, negative marker)
SITES: Dict[str, Tuple[str, Optional[str], Optional[str]]] = {
    "github": ("https://github.com/{u}", '<span class="p-nickname"', "Not Found"),
    "gitlab": ("https://gitlab.com/{u}", "profile-header", "404"),
    "reddit": ("https://www.reddit.com/user/{u}/about.json", '"name"', "Not Found"),
    "hackernews": ("https://hacker-news.firebaseio.com/v0/user/{u}.json", '"id"', "null"),
    "keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?username={u}", '"status":{"code":0', "USER_NOT_FOUND"),
    "pypi": ("https://pypi.org/user/{u}/", "package-header", "404"),
    "npm": ("https://www.npmjs.com/~{u}", "profile-details", "404"),
    "dockerhub": ("https://hub.docker.com/v2/users/{u}/", '"username"', '"detail":"Object not found"'),
    "telegram": ("https://t.me/{u}", "tgme_page_title", "tgme_page_icon"),
    "youtube": ("https://www.youtube.com/@{u}", "channelId", "404"),
    "twitch": ("https://www.twitch.tv/{u}", '"isLiveBroadcast"', "404"),
    "soundcloud": ("https://soundcloud.com/{u}", "soundCloudUser", "404"),
    "behance": ("https://www.behance.net/{u}", "profile", "404"),
    "dribbble": ("https://dribbble.com/{u}", "profile-name", "404"),
    "medium": ("https://medium.com/@{u}", "profile", "404"),
    "devto": ("https://dev.to/{u}", "profile-header", "404"),
    "stackoverflow": ("https://stackoverflow.com/users/filter?search={u}", "user-details", None),
    "bitbucket": ("https://bitbucket.org/{u}/", "profile", "404"),
    "codepen": ("https://codepen.io/{u}", "profile", "404"),
    "replit": ("https://replit.com/@{u}", "profile", "404"),
}

EMAIL_DOMAIN_TYPOS = {
    "gmial.com": "gmail.com", "gmai.com": "gmail.com", "gmail.co": "gmail.com",
    "gmail.con": "gmail.com", "gnail.com": "gmail.com", "hotmial.com": "hotmail.com",
    "hotmai.com": "hotmail.com", "yaho.com": "yahoo.com", "yahoo.co": "yahoo.com",
    "outlok.com": "outlook.com", "outlook.co": "outlook.com", "iclod.com": "icloud.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "dispostable.com", "maildrop.cc", "temp-mail.org",
}

logger = get_logger("osint.username")


def check_site(site: str, username: str, timeout: float = 8.0) -> Dict[str, Any]:
    template, positive, negative = SITES[site]
    url = template.format(u=username)
    response = net.http_request(url, timeout=timeout, max_body=64 * 1024)
    entry: Dict[str, Any] = {
        "site": site,
        "url": url,
        "status": response.get("status"),
        "found": None,
        "evidence": None,
    }
    if not response["ok"]:
        entry["error"] = response.get("error") or "request_failed"
        return entry

    body = response.get("body") or ""
    status = response.get("status")

    if status == 404:
        entry["found"] = False
        entry["evidence"] = "HTTP 404"
        return entry
    if negative and negative.lower() in body.lower():
        entry["found"] = False
        entry["evidence"] = f"negative marker '{negative}'"
        return entry
    if positive and positive.lower() in body.lower():
        entry["found"] = True
        entry["evidence"] = f"positive marker '{positive}'"
        return entry
    if status == 200 and not positive:
        entry["found"] = True
        entry["evidence"] = "HTTP 200, no negative marker"
        return entry
    entry["found"] = None
    entry["evidence"] = (
        f"HTTP {status} without a decisive marker — treated as inconclusive rather "
        "than a hit to avoid a false positive"
    )
    return entry


def scan_username(username: str, config: Optional[Config] = None, threads: int = 8,
                  sites: Optional[List[str]] = None, timeout: float = 8.0) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": username,
        "queried_at": now_iso(),
        "findings": [],
        "kind": "username",
    }
    handle = (username or "").strip().lstrip("@")
    if not is_username(handle):
        result.update(
            {
                "error": "invalid_username",
                "message": "Use 2-32 characters of letters, digits, dots, dashes or underscores.",
            }
        )
        return result

    targets = [site for site in (sites or list(SITES.keys())) if site in SITES]

    def probe(site: str) -> Dict[str, Any]:
        return check_site(site, handle, timeout=timeout)

    entries = []
    for site, value, error in run_threaded(probe, targets, threads=max(1, min(threads, 12))):
        if error or not value:
            entries.append({"site": site, "found": None, "error": error or "no_result", "url": SITES[site][0].format(u=handle)})
            continue
        entries.append(value)

    found = [item for item in entries if item.get("found") is True]
    result.update(
        {
            "ok": True,
            "username": handle,
            "checked": len(entries),
            "found_count": len(found),
            "profiles": found,
            "all_results": entries,
        }
    )
    result["summary"] = f"@{handle}: found on {len(found)} of {len(entries)} checked site(s)"
    result["risk"] = "info"
    result["score"] = 0
    if found:
        result["findings"].append(
            {
                "severity": "info",
                "title": f"Public profile on {len(found)} site(s)",
                "detail": ", ".join(item["site"] for item in found[:12]),
            }
        )
    inconclusive = [item for item in entries if item.get("found") is None]
    if inconclusive:
        result["findings"].append(
            {
                "severity": "info",
                "title": f"{len(inconclusive)} site(s) inconclusive",
                "detail": "No decisive marker; re-run or check manually: "
                + ", ".join(item["site"] for item in inconclusive[:10]),
            }
        )
    return result


def analyse_email(email: str, config: Optional[Config] = None) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": email,
        "queried_at": now_iso(),
        "kind": "email",
        "findings": [],
    }
    address = (email or "").strip().lower()
    if not is_email(address):
        result.update({"error": "invalid_email", "message": "Not a syntactically valid email address."})
        return result

    local, _, domain = address.partition("@")
    findings: List[Dict[str, Any]] = result["findings"]
    notes: List[str] = []

    if domain in EMAIL_DOMAIN_TYPOS:
        findings.append(
            {
                "severity": "medium",
                "title": "Probable typo in the email domain",
                "detail": f"'{domain}' is a common misspelling of '{EMAIL_DOMAIN_TYPOS[domain]}'.",
            }
        )
    if domain in DISPOSABLE_DOMAINS:
        findings.append(
            {
                "severity": "low",
                "title": "Disposable email domain",
                "detail": f"{domain} is a throwaway mailbox provider; the address can vanish at any time.",
            }
        )
    if "+" in local:
        notes.append("plus-addressing present (useful for filtering, also a common alias trick)")
    if re.fullmatch(r"\d{6,}", local):
        notes.append("local part is all digits, common in automated or placeholder addresses")

    result.update(
        {
            "ok": True,
            "email": address,
            "local_part": local,
            "domain": domain,
            "notes": notes,
            "exposure": None,
        }
    )

    spec = PROVIDERS["hibp"]
    if config.api_key("hibp"):
        response = api_get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{address}?truncateResponse=false",
            headers={"hibp-api-key": config.api_key("hibp"), "User-Agent": "KING-REAPER-X"},
            timeout=15.0,
        )
        if response.get("status") == 404:
            result["exposure"] = {"breached": False, "breaches": []}
        elif response["ok"] and isinstance(response.get("data"), list):
            breaches = [
                {
                    "name": item.get("Name"),
                    "title": item.get("Title"),
                    "date": item.get("BreachDate"),
                    "data_classes": item.get("DataClasses") or [],
                }
                for item in response["data"]
            ]
            result["exposure"] = {"breached": bool(breaches), "breaches": breaches}
            if breaches:
                findings.append(
                    {
                        "severity": "high",
                        "title": f"Address appears in {len(breaches)} public breach(es)",
                        "detail": ", ".join(str(item["name"]) for item in breaches[:8]),
                        "reference": "https://haveibeenpwned.com/",
                    }
                )
        else:
            result["exposure"] = {
                "ok": False,
                "degraded": True,
                "provider": "hibp",
                "error": response.get("error") or "provider_error",
                "message": "HIBP did not return data; check key validity and quota.",
            }
    else:
        result["exposure"] = {
            "ok": False,
            "degraded": True,
            "provider": "hibp",
            "requires": spec.env_var,
            "message": (
                "Breach lookup needs HIBP_API_KEY. Structural analysis above did "
                "not require it and is complete."
            ),
        }

    result["summary"] = (
        f"{address}: domain={domain}"
        + (f", {len(result['exposure']['breaches'])} breach(es)" if (result.get("exposure") or {}).get("breaches") else "")
    )
    result["risk"] = "high" if any(f["severity"] == "high" for f in findings) else ("medium" if findings else "info")
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    result["score"] = min(100, sum(weights.get(f["severity"], 0) for f in findings))
    return result


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    value = (target or "").strip()
    if "@" in value:
        return analyse_email(value, config=config)
    return scan_username(
        value,
        config=config,
        threads=int(options.get("threads", 8) or 8),
        sites=options.get("sites"),
        timeout=float(options.get("timeout", 8.0) or 8.0),
    )
