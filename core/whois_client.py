"""WHOIS over raw TCP port 43 — no external ``whois`` binary required.

Termux has no ``whois`` package by default and Kali ships one whose output format
differs per TLD, so we speak the protocol ourselves and parse the key/value pairs
we can actually rely on.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from .utils import is_domain, is_ip, now_iso

IANA_SERVER = "whois.iana.org"

#: TLD -> authoritative WHOIS server. Kept short on purpose: anything missing
#: falls back to the IANA referral, which is the correct generic behaviour.
TLD_SERVERS: Dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "ai": "whois.nic.ai",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "shop": "whois.nic.shop",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "store": "whois.nic.store",
    "cloud": "whois.nic.cloud",
    "pk": "whois.pknic.net.pk",
}

KEY_MAP: Dict[str, str] = {
    "domain name": "domain",
    "registrar": "registrar",
    "registrar url": "registrar_url",
    "registrar iana id": "registrar_iana",
    "creation date": "created",
    "created": "created",
    "created on": "created",
    "registry expiry date": "expires",
    "registrar registration expiration date": "expires",
    "expiry date": "expires",
    "expires on": "expires",
    "updated date": "updated",
    "last updated": "updated",
    "last updated on": "updated",
    "name server": "name_servers",
    "nserver": "name_servers",
    "dnssec": "dnssec",
    "status": "status",
    "domain status": "status",
    "registrant organization": "registrant_org",
    "registrant country": "registrant_country",
    "org": "registrant_org",
    "country": "registrant_country",
    "netname": "netname",
    "inetnum": "inetnum",
    "inet6num": "inetnum",
    "descr": "description",
    "mnt-by": "maintainer",
    "origin": "origin_as",
    "asn": "asn",
    "abuse-mailbox": "abuse_contact",
}

LIST_KEYS = {"name_servers", "status", "description"}


def _query(server: str, query: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Send one WHOIS query. Returns ``{ok, text, error}``."""
    sock = None
    try:
        sock = socket.create_connection((server, 43), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks: List[bytes] = []
        while True:
            try:
                piece = sock.recv(4096)
            except socket.timeout:
                break
            if not piece:
                break
            chunks.append(piece)
            if sum(len(chunk) for chunk in chunks) > 512 * 1024:
                break
        text = b"".join(chunks).decode("utf-8", "replace")
        return {"ok": True, "text": text, "error": None}
    except socket.timeout:
        return {"ok": False, "text": "", "error": "timeout"}
    except (socket.gaierror, OSError) as exc:
        return {"ok": False, "text": "", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _referral(text: str) -> Optional[str]:
    for line in text.splitlines():
        lowered = line.lower()
        for key in ("refer:", "whois:", "referralserver:"):
            if lowered.startswith(key):
                value = line.split(":", 1)[1].strip().split()[0] if line.split(":", 1)[1].strip() else ""
                if value and "." in value:
                    return value
    return None


def parse_whois(text: str) -> Dict[str, Any]:
    """Flatten a WHOIS response into a dict, keeping the raw text aside."""
    parsed: Dict[str, Any] = {}
    free_text: List[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("%", "#", ">>>", "--")):
            continue
        if ":" not in line:
            free_text.append(line.strip())
            continue
        key, _, value = line.partition(":")
        field = KEY_MAP.get(key.strip().lower())
        if not field:
            continue
        value = value.strip()
        if not value:
            continue
        if field in LIST_KEYS:
            bucket = parsed.setdefault(field, [])
            lowered = value.lower()
            if lowered not in [str(item).lower() for item in bucket]:
                bucket.append(value)
        else:
            parsed.setdefault(field, value)
    if free_text:
        parsed["notes"] = free_text[:5]
    return parsed


def whois_domain(domain: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Full WHOIS for a domain: IANA referral + the TLD registry."""
    domain = (domain or "").strip().lower().rstrip(".")
    result: Dict[str, Any] = {
        "ok": False,
        "target": domain,
        "kind": "domain",
        "server": None,
        "data": {},
        "raw_length": 0,
        "error": None,
        "queried_at": now_iso(),
    }
    if not is_domain(domain):
        result["error"] = "not_a_domain"
        result["message"] = f"'{domain}' is not a valid registrable domain name."
        return result

    tld = domain.rsplit(".", 1)[-1]
    server = TLD_SERVERS.get(tld)
    response: Dict[str, Any]
    if server:
        response = _query(server, domain, timeout)
    else:
        iana = _query(IANA_SERVER, tld, timeout)
        referral = _referral(iana.get("text", "")) if iana["ok"] else None
        if not referral:
            response = _query(IANA_SERVER, domain, timeout)
            server = IANA_SERVER
        else:
            server = referral
            response = _query(server, domain, timeout)

    if not response["ok"]:
        result["error"] = response["error"] or "query_failed"
        result["server"] = server
        return result

    text = response["text"]
    # A thin registry replies with a referral; follow it once for richer data.
    referral = _referral(text)
    if referral and referral != server:
        second = _query(referral, domain, timeout)
        if second["ok"] and len(second["text"]) > len(text):
            text = second["text"]
            server = referral

    result["ok"] = bool(text.strip())
    result["server"] = server
    result["raw_length"] = len(text)
    result["data"] = parse_whois(text)
    if not result["ok"]:
        result["error"] = "empty_response"
    return result


def whois_ip(ip: str, timeout: float = 10.0) -> Dict[str, Any]:
    """WHOIS for an IP: IANA -> RIR -> the RIR's own reference."""
    ip = (ip or "").strip()
    result: Dict[str, Any] = {
        "ok": False,
        "target": ip,
        "kind": "ip",
        "server": None,
        "data": {},
        "raw_length": 0,
        "error": None,
        "queried_at": now_iso(),
    }
    if not is_ip(ip):
        result["error"] = "not_an_ip"
        result["message"] = f"'{ip}' is not a valid IP address."
        return result

    iana = _query(IANA_SERVER, ip, timeout)
    server = _referral(iana.get("text", "")) if iana["ok"] else None
    if not server:
        result["error"] = "no_rir_found"
        result["server"] = IANA_SERVER
        return result
    response = _query(server, ip, timeout)
    if not response["ok"]:
        result["error"] = response["error"] or "query_failed"
        result["server"] = server
        return result

    text = response["text"]
    referral = _referral(text)
    if referral and referral != server:
        second = _query(referral, ip, timeout)
        if second["ok"] and len(second["text"]) > len(text):
            text = second["text"]
            server = referral

    result["ok"] = bool(text.strip())
    result["server"] = server
    result["raw_length"] = len(text)
    result["data"] = parse_whois(text)
    if not result["ok"]:
        result["error"] = "empty_response"
    return result


def availability_hint(whois_result: Dict[str, Any]) -> Optional[bool]:
    """Infer whether a domain looks unregistered, from the registry's own text.

    Deliberately conservative: returns ``None`` when there is no clear signal,
    because a wrong "available" claim is worse than no answer.
    """
    if not whois_result.get("ok"):
        return None
    data = whois_result.get("data") or {}
    text = " ".join(str(value) for value in data.values()).lower()
    for marker in (
        "no match for",
        "not found",
        "no entries found",
        "domain not found",
        "status: free",
        "available for registration",
    ):
        if marker in text:
            return True
    if data.get("registrar") or data.get("created"):
        return False
    return None
