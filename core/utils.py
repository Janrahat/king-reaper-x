"""Validation, concurrency and formatting helpers.

No third party imports: this file must load on a bare Termux install.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# time / formatting
# --------------------------------------------------------------------------- #


def now_iso() -> str:
    """UTC timestamp, second precision, ``Z`` suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024.0:
            return f"{num:.0f}{unit}" if unit == "B" else f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}TB"


def truncate(text: str, limit: int = 400, suffix: str = "…") -> str:
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + suffix


def mask_secret(value: Optional[str]) -> str:
    """Never echo a credential back in full, not even in a report."""
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-3:]}"


def parse_int(value: Any, default: int, minimum: int = 0, maximum: int = 10**9) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def dedupe(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


# --------------------------------------------------------------------------- #
# target validation
# --------------------------------------------------------------------------- #

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def is_domain(value: str) -> bool:
    candidate = (value or "").strip().rstrip(".")
    if not candidate or is_ip(candidate):
        return False
    return bool(DOMAIN_RE.match(candidate))


def is_hostname(value: str) -> bool:
    candidate = (value or "").strip().rstrip(".")
    if not candidate:
        return False
    return bool(HOSTNAME_RE.match(candidate)) or is_ip(candidate)


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.match((value or "").strip()))


def is_username(value: str) -> bool:
    return bool(USERNAME_RE.match((value or "").strip()))


def normalize_target(value: str) -> str:
    """Turn a URL, host or host:port into a bare lowercase hostname.

    ``https://Example.com:8443/path?q=1`` -> ``example.com``
    """
    if not value:
        return ""
    target = str(value).strip()
    if "//" in target:
        target = target.split("//", 1)[1]
    target = target.split("/", 1)[0]
    target = target.split("?", 1)[0].split("#", 1)[0]
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        if port.isdigit():
            target = host
    if target.startswith("[") and "]" in target:  # IPv6 literal
        target = target[1 : target.index("]")]
    return target.rstrip(".").lower()


def split_host_port(value: str, default_port: int = 443) -> Tuple[str, int]:
    target = (value or "").strip()
    if "//" in target:
        target = target.split("//", 1)[1]
    target = target.split("/", 1)[0]
    if target.startswith("[") and "]" in target:
        host, _, rest = target[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, parse_int(port, default_port, 1, 65535)
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        return host, parse_int(port, default_port, 1, 65535)
    return target, default_port


# --------------------------------------------------------------------------- #
# DNS resolution (used by scanners, kept here so tests can monkeypatch it)
# --------------------------------------------------------------------------- #


def resolve_host(host: str, timeout: float = 3.0) -> List[str]:
    """Return every A/AAAA address for *host*. Never raises."""
    host = (host or "").strip()
    if not host:
        return []
    if is_ip(host):
        return [host]
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    finally:
        socket.setdefaulttimeout(previous)
    return dedupe([info[4][0] for info in infos])


def reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


# --------------------------------------------------------------------------- #
# ports
# --------------------------------------------------------------------------- #

TOP_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 587, 623, 631, 636,
    873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3128,
    3260, 3306, 3389, 3690, 4000, 4369, 4443, 4505, 4506, 5000, 5432, 5555,
    5601, 5672, 5900, 5984, 6000, 6379, 6443, 7001, 7002, 7077, 8000, 8008,
    8009, 8010, 8032, 8042, 8069, 8080, 8081, 8086, 8088, 8090, 8123, 8161,
    8180, 8200, 8443, 8500, 8529, 8880, 8888, 9000, 9001, 9042, 9090, 9092,
    9100, 9200, 9300, 9418, 9443, 10000, 10250, 11211, 15672, 27017, 27018,
    50000, 50070,
)

PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "node", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "k8s-api",
    8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "php-fpm", 9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb",
}


def parse_ports(spec: Any, limit: int = 65535) -> List[int]:
    """Parse ``top``, ``all``, ``80``, ``22,80,443``, ``1-1024``.

    Raises :class:`ValueError` on garbage so the CLI can exit 2 with a clean
    message instead of a traceback.
    """
    if spec is None or spec == "":
        return list(TOP_PORTS)
    if isinstance(spec, (list, tuple, set)):
        ports: List[int] = []
        for item in spec:
            ports.extend(parse_ports(item, limit=limit))
        return dedupe(ports)[:limit]

    text = str(spec).strip().lower()
    if text in ("top", "default", "common"):
        return list(TOP_PORTS)
    if text in ("all", "full", "*"):
        return list(range(1, min(limit, 65535) + 1))

    ports = []
    for chunk in text.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            low_text, _, high_text = chunk.partition("-")
            if not (low_text.isdigit() and high_text.isdigit()):
                raise ValueError(f"invalid port range: {chunk!r}")
            low, high = int(low_text), int(high_text)
            if low > high:
                low, high = high, low
            if low < 1 or high > 65535:
                raise ValueError(f"port range out of bounds: {chunk!r}")
            ports.extend(range(low, high + 1))
        else:
            if not chunk.isdigit():
                raise ValueError(f"invalid port: {chunk!r}")
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"port out of bounds: {chunk!r}")
            ports.append(port)
    if not ports:
        raise ValueError(f"no ports parsed from {spec!r}")
    return dedupe(ports)[:limit]


def service_name(port: int) -> str:
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------- #
# rate limiting + threading
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Token bucket with a lock; ``rate`` is requests per second."""

    def __init__(self, rate: float = 0.0) -> None:
        self.rate = max(0.0, float(rate or 0.0))
        self.interval = (1.0 / self.rate) if self.rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if self._next <= now:
                self._next = now + self.interval
                return
            delay = self._next - now
            self._next += self.interval
        time.sleep(delay)


def run_threaded(
    func: Callable[[Any], Any],
    items: Sequence[Any],
    threads: int = 8,
    limiter: Optional[RateLimiter] = None,
    on_progress: Optional[Callable[[int, Any, Any, Optional[str]], None]] = None,
) -> List[Tuple[Any, Any, Optional[str]]]:
    """Map *func* over *items* with a bounded pool.

    Returns ``[(item, value, error), ...]`` in input order. A failing item never
    aborts the batch: its error is recorded and the rest keep running.
    """
    items = list(items)
    if not items:
        return []
    results: List[Any] = [None] * len(items)
    errors: List[Optional[str]] = [None] * len(items)
    progress_lock = threading.Lock()

    def work(index: int) -> None:
        item = items[index]
        try:
            if limiter is not None:
                limiter.wait()
            results[index] = func(item)
        except Exception as exc:  # noqa: BLE001 - one bad item must not kill the batch
            errors[index] = f"{type(exc).__name__}: {exc}"
        if on_progress is not None:
            with progress_lock:
                try:
                    on_progress(index, item, results[index], errors[index])
                except Exception:  # noqa: BLE001 - progress rendering must never break a scan
                    pass

    workers = max(1, min(int(threads or 1), len(items)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, range(len(items))))

    return [(items[i], results[i], errors[i]) for i in range(len(items))]


# --------------------------------------------------------------------------- #
# json helpers
# --------------------------------------------------------------------------- #


def to_json(payload: Any, indent: int = 2) -> str:
    def default(obj: Any) -> Any:
        if isinstance(obj, (set, tuple)):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.decode("utf-8", "replace")
        return str(obj)

    return json.dumps(payload, indent=indent, default=default, ensure_ascii=False)


def from_json(text: str, default: Any = None) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def env_flag(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in ("1", "true", "yes", "on")
