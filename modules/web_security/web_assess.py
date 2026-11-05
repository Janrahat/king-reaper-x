"""Web security header assessment, exposed-path checks and cookie hygiene.

Passive with respect to the target in the sense that it performs one ordinary GET
per URL plus a small, fixed set of well-known public paths. No payloads, no
injection attempts, no brute force — this reports missing hardening, it does not
exploit.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import Config
from core.utils import is_hostname, now_iso, run_threaded, split_host_port

NAME = "webscan"
TITLE = "Web Security Assessment"
DESCRIPTION = "Security headers, cookie flags, information disclosure and exposed sensitive paths"
CATEGORY = "web"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

REQUIRED_HEADERS = [
    ("strict-transport-security", "high", "HSTS missing",
     "Without Strict-Transport-Security a downgrade to plain HTTP stays possible for up to the HSTS max-age.",
     "OWASP Secure Headers Project"),
    ("content-security-policy", "medium", "CSP missing",
     "No Content-Security-Policy means any injected script executes unchecked.",
     "OWASP CSP Cheat Sheet"),
    ("x-content-type-options", "low", "X-Content-Type-Options missing",
     "Browsers may MIME-sniff responses, allowing a text upload to run as script.",
     "OWASP Secure Headers Project"),
    ("x-frame-options", "medium", "Clickjacking protection missing",
     "Neither X-Frame-Options nor a frame-ancestors CSP directive is set.",
     "OWASP Clickjacking Defence"),
    ("referrer-policy", "low", "Referrer-Policy missing",
     "Full URLs, potentially including tokens, leak to third parties.",
     "W3C Referrer Policy"),
    ("permissions-policy", "low", "Permissions-Policy missing",
     "Browser features such as camera and geolocation are not restricted.",
     "W3C Permissions Policy"),
]

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache")

#: Exactly four paths, all documented public conventions. Not a directory buster.
SENSITIVE_PATHS = ["/.git/config", "/.env", "/server-status", "/phpinfo.php"]


def _header_findings(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for name, severity, title, detail, reference in REQUIRED_HEADERS:
        if name in headers:
            continue
        if name == "x-frame-options" and "frame-ancestors" in str(
            headers.get("content-security-policy", "")
        ).lower():
            continue
        findings.append(
            {"severity": severity, "title": title, "detail": f"Header '{name}' absent. {detail}",
             "reference": reference}
        )
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts)
        if match and int(match.group(1)) < 15552000:
            findings.append(
                {
                    "severity": "low",
                    "title": f"HSTS max-age too short ({match.group(1)}s)",
                    "detail": "Use max-age=31536000; includeSubDomains for a meaningful protection window.",
                    "reference": "OWASP HSTS Cheat Sheet",
                }
            )
    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        if value:
            findings.append(
                {
                    "severity": "low",
                    "title": f"Information disclosure via {header}",
                    "detail": f"{header}: {str(value)[:100]}",
                }
            )
    return findings


def _cookie_findings(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    raw = headers.get("set-cookie")
    if not raw:
        return []
    findings: List[Dict[str, Any]] = []
    cookies = re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", str(raw))
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip() or "cookie"
        lowered = cookie.lower()
        if "secure" not in lowered:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Cookie '{name}' without Secure flag",
                    "detail": "The cookie can be sent over plain HTTP and intercepted in transit.",
                    "reference": "OWASP Session Management",
                }
            )
        if "httponly" not in lowered:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Cookie '{name}' without HttpOnly flag",
                    "detail": "JavaScript can read the cookie, so any XSS becomes session theft.",
                    "reference": "OWASP Session Management",
                }
            )
        if "samesite" not in lowered:
            findings.append(
                {
                    "severity": "low",
                    "title": f"Cookie '{name}' without SameSite attribute",
                    "detail": "Cross-site requests may carry the cookie, enabling CSRF.",
                    "reference": "RFC 6265bis",
                }
            )
    return findings


def _check_paths(base: str, timeout: float, threads: int = 4) -> List[Dict[str, Any]]:
    """Fetch each well-known path and report only unambiguous exposures."""

    def probe(path: str) -> Optional[Dict[str, Any]]:
        response = net.http_request(base + path, timeout=timeout, max_body=8192)
        if not response["ok"]:
            return None
        status = response.get("status")
        body = response.get("body") or ""
        if status != 200:
            return None
        # A single-page-app catch-all answers 200 with the app shell for any
        # path, which is not an exposure. Require content that proves it.
        proofs = {
            "/.git/config": ("[core]", "repositoryformatversion"),
            "/.env": ("=", "APP_", "SECRET", "DB_", "API"),
            "/server-status": ("apache server status", "server status"),
            "/phpinfo.php": ("php version", "phpinfo()"),
        }
        markers = proofs.get(path, ())
        lowered = body.lower()
        if not any(marker.lower() in lowered for marker in markers):
            return None
        return {
            "path": path,
            "status": status,
            "evidence": re.sub(r"\s+", " ", body)[:160],
        }

    hits: List[Dict[str, Any]] = []
    for path, value, _error in run_threaded(probe, SENSITIVE_PATHS, threads=threads):
        if value:
            hits.append(value)
    return hits


def assess(
    target: str,
    config: Optional[Config] = None,
    timeout: float = 12.0,
    check_paths: bool = True,
) -> Dict[str, Any]:
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
        result.update({"error": "bad_target", "message": f"'{target}' is not a valid host."})
        return result

    # Refuse any scheme we cannot actually speak. Without this an ``ftp://`` or
    # ``ssh://`` target silently becomes ``https://host`` and the operator gets
    # a report about a different service than the one they asked about.
    declared = str(target or "").split("://", 1)
    if len(declared) == 2:
        scheme_name = declared[0].strip().lower()
        if scheme_name not in ("http", "https"):
            result.update({
                "error": "unsupported_scheme",
                "message": (
                    f"'{scheme_name}://' is not supported; this module assesses "
                    "HTTP(S) endpoints. Use the ssl module for TLS-only targets "
                    "or the ports module for raw TCP."
                ),
            })
            return result
        port = 443 if scheme_name == "https" and port in (80, 443) else port

    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

    response = net.http_request(base, timeout=timeout, max_body=128 * 1024)
    if not response["ok"]:
        result.update(
            {
                "error": "unreachable",
                "message": f"{base} did not answer: {response.get('error') or 'no response'}",
            }
        )
        return result

    headers = response.get("headers") or {}
    findings: List[Dict[str, Any]] = result["findings"]
    findings.extend(_header_findings(headers))
    findings.extend(_cookie_findings(headers))

    final_url = str(response.get("final_url") or base)
    if final_url.startswith("http://") and "https" not in (response.get("redirects") or [{}])[0].get("to", ""):
        findings.append(
            {
                "severity": "high",
                "title": "Served over plain HTTP",
                "detail": f"{base} responds on HTTP and does not redirect to HTTPS.",
                "reference": "OWASP Transport Layer Protection",
            }
        )

    result.update(
        {
            "ok": True,
            "url": final_url,
            "status": response.get("status"),
            "server": headers.get("server"),
            "headers": headers,
            "security_headers_present": [
                name for name, *_ in REQUIRED_HEADERS if name in headers
            ],
        }
    )

    if check_paths:
        exposures = _check_paths(base, timeout)
        result["exposed_paths"] = exposures
        for item in exposures:
            severity = "critical" if item["path"] in ("/.env", "/.git/config") else "high"
            findings.append(
                {
                    "severity": severity,
                    "title": f"Sensitive path exposed: {item['path']}",
                    "detail": (
                        f"HTTP 200 with matching content at {item['path']}. "
                        "Remove it from the document root and rotate any secrets it contains."
                    ),
                    "reference": "OWASP Testing Guide OTG-CONFIG",
                }
            )
    else:
        result["exposed_paths"] = []

    result["summary"] = (
        f"{host}: {len(findings)} issue(s), {len(result['security_headers_present'])}/"
        f"{len(REQUIRED_HEADERS)} security headers set"
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
    return assess(
        target,
        config=config,
        timeout=float(options.get("timeout", 12.0) or 12.0),
        check_paths=bool(options.get("check_paths", True)),
    )
