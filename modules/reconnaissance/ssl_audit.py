"""TLS/SSL certificate and configuration analysis."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import Config
from core.utils import is_hostname, now_iso, split_host_port

NAME = "ssl"
TITLE = "TLS / SSL Audit"
DESCRIPTION = "Certificate chain summary, SAN coverage, expiry and TLS version support"
CATEGORY = "recon"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
STRONG_CIPHER_MARKERS = ("AES", "CHACHA20", "GCM")


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(str(value).strip(), fmt)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)
        except ValueError:
            continue
    return None


def _san_names(sans: List[str]) -> List[str]:
    out = []
    for entry in sans:
        if ":" in entry:
            kind, _, value = entry.partition(":")
            if kind.strip().upper() in ("DNS", "IP ADDRESS"):
                out.append(value.strip())
    return out


def _hostname_matches(host: str, names: List[str]) -> bool:
    host = host.lower().strip()
    for name in names:
        candidate = name.lower().strip()
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
    return False


def inspect(target: str, config: Optional[Config] = None, timeout: float = 10.0) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": target,
        "queried_at": now_iso(),
        "findings": [],
    }
    host, port = split_host_port(target, default_port=443)
    if not is_hostname(host):
        result.update({"error": "bad_target", "message": f"'{target}' is not a valid hostname."})
        return result

    certificate = net.get_certificate(host, port, timeout=timeout)
    result["host"] = host
    result["port"] = port

    if not certificate.get("ok"):
        result.update(
            {
                "error": "tls_unreachable",
                "message": (
                    f"Could not complete a TLS handshake with {host}:{port} — "
                    f"{certificate.get('error') or 'no certificate returned'}. "
                    "The port may not serve TLS, or a firewall may block it."
                ),
            }
        )
        return result

    subject = certificate.get("subject") or {}
    issuer = certificate.get("issuer") or {}
    san_names = _san_names(certificate.get("subject_alt_names") or [])
    not_before = _parse_date(certificate.get("not_before"))
    not_after = _parse_date(certificate.get("not_after"))
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days if not_after else None

    covers_host = _hostname_matches(host, san_names)

    result.update(
        {
            "ok": True,
            "protocol": certificate.get("protocol"),
            "cipher": certificate.get("cipher"),
            "subject": subject,
            "issuer": issuer,
            "common_name": subject.get("commonName"),
            "san": san_names,
            "not_before": certificate.get("not_before"),
            "not_after": certificate.get("not_after"),
            "days_remaining": days_left,
            "covers_hostname": covers_host,
            "self_signed": bool(certificate.get("self_signed")),
            "serial": certificate.get("serial_number"),
            "decoded": bool(certificate.get("decoded")),
        }
    )

    tls_versions = net.check_tls_versions(host, port, timeout=min(timeout, 6.0))
    result["tls_versions"] = tls_versions

    findings: List[Dict[str, Any]] = result["findings"]
    if not certificate.get("decoded"):
        findings.append(
            {
                "severity": "info",
                "title": "Certificate metadata could not be decoded",
                "detail": (
                    "This Python build lacks the private certificate decoder. The "
                    "handshake succeeded but subject/SAN details are unavailable."
                ),
            }
        )
    if result["self_signed"]:
        findings.append(
            {
                "severity": "high",
                "title": "Self-signed certificate",
                "detail": "No public CA vouches for this certificate, so clients cannot verify the server identity.",
                "reference": "CAB Forum Baseline Requirements",
            }
        )
    elif not covers_host:
        findings.append(
            {
                "severity": "high",
                "title": "Certificate does not cover this hostname",
                "detail": (
                    f"SAN list does not include {host}. Browsers will show a name "
                    "mismatch error. SANs: " + ", ".join(san_names[:6] or ["none"])
                ),
                "reference": "RFC 6125 §6.4",
            }
        )
    if days_left is not None:
        if days_left < 0:
            findings.append(
                {
                    "severity": "critical",
                    "title": "Certificate expired",
                    "detail": f"Expired {abs(days_left)} day(s) ago ({certificate.get('not_after')}).",
                }
            )
        elif days_left <= 14:
            findings.append(
                {
                    "severity": "high",
                    "title": f"Certificate expires in {days_left} day(s)",
                    "detail": f"Renew before {certificate.get('not_after')}.",
                }
            )
        elif days_left <= 30:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Certificate expires in {days_left} day(s)",
                    "detail": f"Renewal window is open ({certificate.get('not_after')}).",
                }
            )
    if tls_versions.get("TLSv1.2") is False and tls_versions.get("TLSv1.3") is False:
        findings.append(
            {
                "severity": "medium",
                "title": "Neither TLS 1.2 nor 1.3 accepted for a forced handshake",
                "detail": "The server would not complete a modern TLS handshake when pinned to a single version.",
            }
        )
    cipher = str(result.get("cipher") or "").upper()
    if cipher and not any(marker in cipher for marker in STRONG_CIPHER_MARKERS):
        findings.append(
            {
                "severity": "low",
                "title": f"Non-AEAD cipher negotiated: {cipher}",
                "detail": "Prefer AES-GCM or ChaCha20-Poly1305 cipher suites.",
                "reference": "RFC 8446 Annex B",
            }
        )

    result["summary"] = (
        f"{host}:{port} — CN={result['common_name'] or 'n/a'}, issuer={issuer.get('organizationName') or issuer.get('commonName') or 'unknown'}, "
        f"{days_left if days_left is not None else '?'} day(s) left, {result.get('protocol')}"
    )
    result["risk"] = _risk(findings)
    result["score"] = _score(findings)
    return result


def _risk(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(str(item.get("severity", "info")).lower(), 0) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst]


def _score(findings: List[Dict[str, Any]]) -> int:
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    return min(100, sum(weights.get(str(item.get("severity", "info")).lower(), 0) for item in findings))


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return inspect(target, config=config, timeout=float(options.get("timeout", 10.0) or 10.0))
