"""Domain reconnaissance: registrar, DNS, mail topology, hosting.

Combines the bundled WHOIS client and DNS client — no ``dig``, no ``whois``
binary, so it runs identically on Kali and on Termux.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core import dnsclient, whois_client
from core.config import Config
from core.utils import is_domain, now_iso, resolve_host

NAME = "domain"
TITLE = "Domain Intelligence"
DESCRIPTION = "Registrar, DNS records, nameservers, mail topology and hosting for a domain"
CATEGORY = "recon"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]


def _records(domain: str, timeout: float) -> Dict[str, Any]:
    collected = dnsclient.resolve_all(domain, timeout=timeout, types=RECORD_TYPES)
    flat: Dict[str, List[str]] = {}
    for rtype, entries in (collected.get("records") or {}).items():
        values = []
        for entry in entries:
            value = entry.get("value")
            if value is None:
                continue
            if isinstance(value, dict):
                value = value.get("mname") or str(value)
            values.append(str(value))
        if values:
            flat[rtype] = values
    return {"ok": collected.get("ok", False), "records": flat, "errors": collected.get("errors") or {}}


def _spf_dmarc(records: Dict[str, List[str]]) -> Dict[str, Any]:
    txt = [item for item in records.get("TXT", []) if item]
    spf = [item for item in txt if item.lower().startswith("v=spf1")]
    dmarc_hint = [item for item in txt if "v=dmarc1" in item.lower()]
    return {
        "spf": spf[0] if spf else None,
        "spf_present": bool(spf),
        "spf_multiple": len(spf) > 1,
        "dmarc_on_root_txt": dmarc_hint[0] if dmarc_hint else None,
        "dkim_note": "DKIM selectors are per-provider; query _domainkey with --dkim-selector.",
    }


def analyse(domain: str, config: Optional[Config] = None, timeout: float = 8.0) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": domain,
        "queried_at": now_iso(),
        "findings": [],
    }
    name = (domain or "").strip().lower().rstrip(".")
    if not is_domain(name):
        result.update(
            {"error": "not_a_domain", "message": f"'{domain}' is not a valid registrable domain."}
        )
        return result

    # --- DNS ------------------------------------------------------------- #
    dns_data = _records(name, timeout)
    records = dns_data["records"]
    result["dns"] = records
    result["dns_errors"] = dns_data["errors"]

    if not records:
        result.update(
            {
                "error": "no_dns_records",
                "message": (
                    f"No DNS records resolved for {name}. The domain may be "
                    "unregistered, expired or parked without records."
                ),
            }
        )
        return result

    # --- WHOIS ----------------------------------------------------------- #
    who = whois_client.whois_domain(name, timeout=max(timeout, 10.0))
    result["whois"] = {
        "ok": who.get("ok"),
        "server": who.get("server"),
        "error": who.get("error"),
        "data": who.get("data") or {},
        "available_hint": whois_client.availability_hint(who),
    }

    # --- derived --------------------------------------------------------- #
    addresses = records.get("A", []) + records.get("AAAA", [])
    result["resolves"] = bool(addresses)
    result["addresses"] = addresses

    nameservers = records.get("NS", [])
    result["nameservers"] = nameservers
    mx = records.get("MX", [])
    result["mail"] = {
        "mx": mx,
        "has_mail": bool(mx),
        "spf": _spf_dmarc(records),
        "null_mx": any(str(item).strip().startswith("0 .") for item in mx),
    }

    txt_records = records.get("TXT", [])
    result["verification_tokens"] = [
        item for item in txt_records
        if any(marker in item.lower() for marker in ("google-site-verification", "ms=", "facebook-domain", "atlassian"))
    ]

    whois_data = result["whois"]["data"]
    result["registrar"] = whois_data.get("registrar")
    result["created"] = whois_data.get("created")
    result["expires"] = whois_data.get("expires")
    result["status"] = whois_data.get("status") or []
    result["dnssec"] = whois_data.get("dnssec") or ("signedDelegation" in str(records.get("CAA", [])) if records.get("CAA") else None)

    # --- findings -------------------------------------------------------- #
    findings: List[Dict[str, Any]] = result["findings"]
    if not nameservers:
        findings.append(
            {
                "severity": "medium",
                "title": "No NS records",
                "detail": "The domain has no authoritative nameservers visible, so it cannot serve DNS.",
            }
        )
    if nameservers and len(nameservers) == 1:
        findings.append(
            {
                "severity": "low",
                "title": "Single nameserver",
                "detail": f"Only {nameservers[0]} is authoritative. A second NS avoids an outage if it fails.",
            }
        )
    spf = result["mail"]["spf"]
    if result["mail"]["has_mail"] and not spf["spf_present"]:
        findings.append(
            {
                "severity": "medium",
                "title": "Mail accepted without SPF",
                "detail": "MX records exist but no SPF policy was published, so anyone can spoof this domain in email.",
                "reference": "RFC 7208",
            }
        )
    if spf.get("spf_multiple"):
        findings.append(
            {
                "severity": "medium",
                "title": "Multiple SPF records",
                "detail": "More than one v=spf1 record makes the policy invalid and is treated as 'none' by receivers.",
                "reference": "RFC 7208 §3.2",
            }
        )
    if spf.get("spf_present") and "+all" in str(spf.get("spf")).lower():
        findings.append(
            {
                "severity": "high",
                "title": "SPF ends in +all",
                "detail": "Any host on the internet is authorised to send mail as this domain.",
                "reference": "RFC 7208",
            }
        )
    if not result["mail"]["spf"].get("dmarc_on_root_txt"):
        findings.append(
            {
                "severity": "low",
                "title": "No DMARC record on the root domain",
                "detail": "Query _dmarc.<domain> to confirm; a missing DMARC policy leaves spoofed mail unactionable.",
                "reference": "RFC 7489",
            }
        )
    expiry_note = _expiry_note(result.get("expires"))
    if expiry_note:
        findings.append(expiry_note)

    result["ok"] = True
    result["summary"] = (
        f"{name}: {len(addresses)} address(es), {len(nameservers)} NS, "
        f"mail={'yes' if result['mail']['has_mail'] else 'no'}, registrar={result['registrar'] or 'unknown'}"
    )
    result["risk"] = _risk(findings)
    result["score"] = _score(findings)
    return result


def _expiry_note(expires: Optional[str]) -> Optional[Dict[str, Any]]:
    if not expires:
        return None
    import re
    from datetime import datetime, timezone

    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(expires))
    if not match:
        return None
    try:
        when = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
    except ValueError:
        return None
    days = (when - datetime.now(timezone.utc)).days
    if days < 0:
        severity, title = "high", "Domain registration expired"
        detail = f"Expired {abs(days)} day(s) ago per the registry."
    elif days <= 30:
        severity, title = "medium", "Domain expires within 30 days"
        detail = f"Registry expiry is {days} day(s) away ({expires})."
    else:
        return None
    return {"severity": severity, "title": title, "detail": detail, "reference": "WHOIS registry data"}


def _risk(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(str(item.get("severity", "info")).lower(), 0) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst]


def _score(findings: List[Dict[str, Any]]) -> int:
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    return min(100, sum(weights.get(str(item.get("severity", "info")).lower(), 0) for item in findings))


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return analyse(target, config=config, timeout=float(options.get("timeout", 8.0)))
