"""Technology fingerprinting from public HTTP responses.

Identifies servers, frameworks and CMSs from headers, cookies and page markers.
Every detection carries the evidence that produced it, so a wrong guess is
visible rather than authoritative.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import Config
from core.utils import is_hostname, now_iso, split_host_port

NAME = "fingerprint"
TITLE = "Technology Fingerprinting"
DESCRIPTION = "Identify web server, framework, CMS and CDN from headers, cookies and page markers"
CATEGORY = "recon"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

HEADER_RULES: List[Tuple[str, str, str]] = [
    ("server", r"nginx", "nginx"),
    ("server", r"apache", "Apache httpd"),
    ("server", r"microsoft-iis", "Microsoft IIS"),
    ("server", r"litespeed", "LiteSpeed"),
    ("server", r"openresty", "OpenResty"),
    ("server", r"caddy", "Caddy"),
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"gunicorn", "Gunicorn"),
    ("server", r"werkzeug", "Werkzeug (Flask dev server)"),
    ("server", r"uvicorn", "Uvicorn (ASGI)"),
    ("x-powered-by", r"php/?([\d.]*)", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express (Node.js)"),
    ("x-powered-by", r"next\.js", "Next.js"),
    ("x-generator", r"drupal", "Drupal"),
    ("x-drupal-cache", r".", "Drupal"),
    ("x-aspnet-version", r".", "ASP.NET"),
    ("x-aspnetmvc-version", r".", "ASP.NET MVC"),
    ("x-shopify-stage", r".", "Shopify"),
    ("x-vercel-id", r".", "Vercel"),
    ("x-amz-cf-id", r".", "Amazon CloudFront"),
    ("x-served-by", r"cache-", "Fastly / Varnish"),
    ("x-github-request-id", r".", "GitHub Pages"),
    ("cf-ray", r".", "Cloudflare"),
    ("x-akamai-transformed", r".", "Akamai"),
    ("x-azure-ref", r".", "Azure Front Door"),
]

COOKIE_RULES: List[Tuple[str, str]] = [
    ("phpsessid", "PHP"),
    ("jsessionid", "Java (Servlet)"),
    ("asp.net_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("ci_session", "CodeIgniter"),
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("django", "Django"),
    ("csrftoken", "Django"),
    ("_shopify", "Shopify"),
    ("__cf_bm", "Cloudflare"),
    ("connect.sid", "Express (Node.js)"),
]

BODY_RULES: List[Tuple[str, str]] = [
    (r'<meta name="generator" content="WordPress ([\d.]+)', "WordPress"),
    (r"wp-content/(?:themes|plugins)/", "WordPress"),
    (r'content="Drupal ([\d.]+)', "Drupal"),
    (r'<meta name="generator" content="Joomla', "Joomla"),
    (r"/sites/default/files/", "Drupal"),
    (r"__NEXT_DATA__", "Next.js"),
    (r'id="___gatsby"', "Gatsby"),
    (r'window\.__NUXT__', "Nuxt.js"),
    (r'ng-version="([\d.]+)"', "Angular"),
    (r'data-reactroot|__REACT_DEVTOOLS', "React"),
    (r"/static/js/main\.[a-f0-9]{6,}\.js", "Create React App"),
    (r'name="csrf-token"', "Rails / Laravel"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"shopify\.theme", "Shopify"),
    (r"cdn\.shopify\.com", "Shopify"),
    (r"magento", "Magento"),
    (r"X-Magento", "Magento"),
    (r"/typo3/", "TYPO3"),
    (r"hubspot", "HubSpot"),
]


def _match_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    for header, pattern, label in HEADER_RULES:
        value = headers.get(header)
        if not value:
            continue
        if re.search(pattern, str(value), re.IGNORECASE):
            hits.append({"tech": label, "source": f"header:{header}", "evidence": str(value)[:120]})
    return hits


def _match_cookies(headers: Dict[str, str]) -> List[Dict[str, str]]:
    raw = str(headers.get("set-cookie") or "").lower()
    if not raw:
        return []
    hits = []
    for marker, label in COOKIE_RULES:
        if marker.lower() in raw:
            hits.append({"tech": label, "source": "cookie", "evidence": marker})
    return hits


def _match_body(body: str) -> List[Dict[str, str]]:
    hits = []
    for pattern, label in BODY_RULES:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            hits.append(
                {"tech": label, "source": "body", "evidence": (match.group(0) or "")[:120]}
            )
    return hits


def _generator_version(body: str) -> Optional[str]:
    match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)', body, re.IGNORECASE)
    return match.group(1) if match else None


def analyse(target: str, config: Optional[Config] = None, timeout: float = 10.0) -> Dict[str, Any]:
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

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    response = net.http_request(url, timeout=timeout, max_body=256 * 1024)
    if not response["ok"]:
        result.update(
            {
                "error": "unreachable",
                "message": f"{url} did not answer: {response.get('error') or 'no response'}",
            }
        )
        return result

    headers = response.get("headers") or {}
    body = response.get("body") or ""
    detections: List[Dict[str, str]] = []
    for bucket in (_match_headers(headers), _match_cookies(headers), _match_body(body)):
        detections.extend(bucket)

    seen = set()
    unique: List[Dict[str, str]] = []
    for item in detections:
        tech = item["tech"]
        if tech in seen:
            continue
        seen.add(tech)
        unique.append(item)

    result.update(
        {
            "ok": True,
            "url": response.get("final_url") or url,
            "status": response.get("status"),
            "server": headers.get("server"),
            "technologies": unique,
            "title": _extract_title(body),
            "generator_version": _generator_version(body),
        }
    )

    version = result["generator_version"]
    findings: List[Dict[str, Any]] = result["findings"]
    if version:
        findings.append(
            {
                "severity": "medium",
                "title": f"WordPress version disclosed: {version}",
                "detail": "Public version disclosure helps attackers target known CVEs for that release.",
            }
        )
    powered = str(headers.get("x-powered-by") or "")
    if powered:
        findings.append(
            {
                "severity": "low",
                "title": f"X-Powered-By discloses stack: {powered}",
                "detail": "Removing this header strips a free hint from attackers.",
            }
        )
    if re.search(r"werkzeug", str(headers.get("server") or ""), re.IGNORECASE):
        findings.append(
            {
                "severity": "high",
                "title": "Werkzeug/Flask development server in production",
                "detail": "The Flask dev server is single-threaded and not hardened; use a WSGI server.",
            }
        )

    result["summary"] = (
        f"{result['url']} — {result['status']}, " + (", ".join(item["tech"] for item in unique) or "no fingerprint match")
    )
    result["risk"] = _risk(findings)
    result["score"] = _score(findings)
    return result


def _extract_title(body: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def _risk(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(str(item.get("severity", "info")).lower(), 0) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst]


def _score(findings: List[Dict[str, Any]]) -> int:
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    return min(100, sum(weights.get(str(item.get("severity", "info")).lower(), 0) for item in findings))


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return analyse(target, config=config, timeout=float(options.get("timeout", 10.0) or 10.0))
