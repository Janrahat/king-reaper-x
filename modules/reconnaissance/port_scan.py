"""TCP port scanning with service identification and risk annotation.

Authorization is enforced twice: by the CLI gate and again here in the module, so
a direct API call cannot bypass it. Default target set is the top 100 ports —
a full 65535 sweep from a phone is slow and noisy.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core import net
from core.config import Config
from core.utils import (
    TOP_PORTS,
    dedupe,
    is_hostname,
    is_private_ip,
    now_iso,
    parse_ports,
    resolve_host,
    run_threaded,
    service_name,
)

NAME = "ports"
TITLE = "Port Scanner"
DESCRIPTION = "TCP connect scan with banner grab and service identification (requires --authorized)"
CATEGORY = "recon"
ACTIVE = True
REQUIRES: Tuple[str, ...] = ()

#: port -> (severity, title, detail)
RISKY_SERVICES: Dict[int, Tuple[str, str, str]] = {
    21: ("high", "FTP exposed", "FTP sends credentials in clear text; prefer SFTP/FTPS."),
    23: ("critical", "Telnet exposed", "Telnet transmits everything in clear text, including passwords."),
    25: ("low", "SMTP reachable", "Confirm open relay is not permitted."),
    135: ("medium", "MSRPC exposed", "Windows RPC should not be reachable from untrusted networks."),
    139: ("medium", "NetBIOS exposed", "Legacy SMB name service; leaks host and share names."),
    445: ("critical", "SMB exposed", "SMB has a long history of remote code execution; never expose to the internet."),
    512: ("high", "rexec exposed", "Legacy clear-text remote execution."),
    513: ("high", "rlogin exposed", "Legacy clear-text remote login."),
    514: ("high", "rsh exposed", "Legacy clear-text remote shell."),
    1433: ("high", "MSSQL exposed", "Database should never be directly internet-facing."),
    2375: ("critical", "Docker daemon (unencrypted) exposed", "Unauthenticated Docker API means instant host takeover."),
    2376: ("high", "Docker daemon exposed", "TLS does not replace network restriction."),
    3306: ("high", "MySQL exposed", "Database should never be directly internet-facing."),
    3389: ("high", "RDP exposed", "Remote Desktop is a top ransomware entry point."),
    5432: ("high", "PostgreSQL exposed", "Database should never be directly internet-facing."),
    5900: ("critical", "VNC exposed", "VNC is frequently unauthenticated."),
    5984: ("high", "CouchDB exposed", "CouchDB has had unauthenticated admin interfaces."),
    6379: ("critical", "Redis exposed", "Unauthenticated Redis allows remote write and code execution."),
    9200: ("critical", "Elasticsearch exposed", "Historically unauthenticated; leaks or overwrites all data."),
    9300: ("high", "Elasticsearch transport exposed", "Cluster transport should be private."),
    11211: ("high", "Memcached exposed", "Used for amplification attacks; must not be public."),
    27017: ("critical", "MongoDB exposed", "Unauthenticated MongoDB exposes every database."),
    5601: ("high", "Kibana exposed", "Often unauthenticated and exposes indexed log data."),
    15672: ("high", "RabbitMQ management exposed", "Management UI should be internal only."),
    9090: ("medium", "Prometheus exposed", "Metrics expose internal topology and credentials."),
    6443: ("medium", "Kubernetes API exposed", "Confirm strong authn/authz and network policy."),
}

CRITICAL_PORTS = {23, 445, 2375, 5900, 6379, 9200, 27017}


def scan(
    target: str,
    config: Optional[Config] = None,
    authorized: bool = False,
    ports: Any = None,
    timeout: float = 2.0,
    threads: int = 100,
    banner: bool = True,
    limiter=None,
) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": target,
        "queried_at": now_iso(),
        "findings": [],
        "open_ports": [],
    }
    if not authorized:
        result.update(
            {
                "error": "authorization_required",
                "message": (
                    "Port scanning requires an explicit authorization confirmation "
                    "for this target. Re-run with --authorized."
                ),
            }
        )
        return result

    host = (target or "").strip()
    if not is_hostname(host):
        result.update({"error": "bad_target", "message": f"'{target}' is not a valid host or IP."})
        return result

    addresses = resolve_host(host, timeout=5.0)
    if not addresses:
        result.update(
            {
                "error": "unresolvable",
                "message": f"{host} does not resolve — nothing to scan.",
            }
        )
        return result
    address = addresses[0]
    result["ip"] = address
    result["private_address"] = is_private_ip(address)

    try:
        port_list = parse_ports(ports, limit=65535)
    except ValueError as exc:
        result.update({"error": "bad_ports", "message": str(exc)})
        return result
    result["ports_requested"] = len(port_list)
    result["port_spec"] = str(ports or "top")

    def probe(port: int) -> Dict[str, Any]:
        return net.probe_port(address, port, timeout=timeout, banner=banner)

    opened: List[Dict[str, Any]] = []
    for port, value, error in run_threaded(
        probe, port_list, threads=max(1, min(threads, 200)), limiter=limiter
    ):
        if error or not value:
            continue
        if value.get("open"):
            entry = {
                "port": value["port"],
                "service": service_name(value["port"]),
                "banner": value.get("banner"),
                "latency_ms": value.get("elapsed_ms"),
            }
            risky = RISKY_SERVICES.get(value["port"])
            if risky:
                entry["exposure"] = risky[0]
            opened.append(entry)

    opened.sort(key=lambda item: item["port"])
    result["ok"] = True
    result["open_ports"] = opened
    result["open_count"] = len(opened)

    findings: List[Dict[str, Any]] = result["findings"]
    for entry in opened:
        risky = RISKY_SERVICES.get(entry["port"])
        if not risky:
            continue
        severity, title, detail = risky
        findings.append(
            {
                "severity": severity,
                "title": f"{title} (port {entry['port']})",
                "detail": f"{detail}"
                + (f" Banner: {entry['banner'][:80]}" if entry.get("banner") else ""),
                "reference": f"TCP/{entry['port']}",
            }
        )

    critical = [entry["port"] for entry in opened if entry["port"] in CRITICAL_PORTS]
    if critical:
        findings.insert(
            0,
            {
                "severity": "critical",
                "title": f"{len(critical)} high-risk service(s) reachable",
                "detail": "Ports: " + ", ".join(str(port) for port in critical),
            },
        )

    result["summary"] = (
        f"{host} ({address}): {len(opened)} open of {len(port_list)} scanned"
        + (f" — critical: {', '.join(str(port) for port in critical)}" if critical else "")
    )
    result["risk"] = _risk(findings)
    result["score"] = _score(findings, len(opened))
    return result


def _risk(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((order.get(str(item.get("severity", "info")).lower(), 0) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst]


def _score(findings: List[Dict[str, Any]], open_count: int) -> int:
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    base = sum(weights.get(str(item.get("severity", "info")).lower(), 0) for item in findings)
    return min(100, base + min(10, open_count))


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return scan(
        target,
        config=config,
        authorized=bool(options.get("authorized", False)),
        ports=options.get("ports"),
        timeout=float(options.get("timeout", 2.0) or 2.0),
        threads=int(options.get("threads", 100) or 100),
        banner=bool(options.get("banner", True)),
    )
