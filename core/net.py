"""Network primitives: TCP connect, banner grab, HTTP, TLS.

Standard library only. Every function returns plain data and never raises for
expected network conditions, so callers (scanners, auditors, the dashboard) can
reason about them without try/except everywhere.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .utils import dedupe, resolve_host

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) KING-REAPER-X/1.0 security-assessment"

MAX_BODY = 512 * 1024


# --------------------------------------------------------------------------- #
# TCP
# --------------------------------------------------------------------------- #


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    """Connect to host:port. Returns elapsed seconds, or ``None`` on failure."""
    start = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        return time.time() - start
    except (socket.timeout, OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_port(host: str, port: int, timeout: float = 3.0, banner: bool = True) -> Dict[str, Any]:
    """Single port probe with a light banner grab."""
    result: Dict[str, Any] = {
        "port": int(port),
        "open": False,
        "banner": None,
        "elapsed_ms": None,
        "error": None,
    }
    start = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        result["open"] = True
        result["elapsed_ms"] = int((time.time() - start) * 1000)
        if banner:
            try:
                sock.settimeout(min(1.5, timeout))
                data = sock.recv(512)
                if data:
                    result["banner"] = data.decode("utf-8", "replace").strip()[:200]
            except (socket.timeout, OSError):
                result["banner"] = None
    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "refused"
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)[:120]
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


class HttpResult(dict):
    """dict subclass so it serialises cleanly while remaining attribute-ish."""


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
    max_body: int = MAX_BODY,
    max_redirects: int = 5,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Perform an HTTP(S) request and return a normalised dict.

    Keys: ``ok, url, final_url, status, reason, headers, body, redirects,
    elapsed_ms, error``. ``ok`` is True when a complete response was received.
    """
    out: Dict[str, Any] = {
        "ok": False,
        "url": url,
        "final_url": url,
        "status": None,
        "reason": None,
        "headers": {},
        "body": "",
        "redirects": [],
        "elapsed_ms": 0,
        "error": None,
        "server": None,
    }

    parsed = urlsplit(url if "//" in url else f"http://{url}")
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        out["error"] = f"unsupported scheme: {scheme}"
        return out
    host = parsed.hostname or ""
    if not host:
        out["error"] = "missing host"
        return out
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if headers:
        for key, value in headers.items():
            request_headers[key] = value

    context = None
    if scheme == "https":
        if verify_tls:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    start = time.time()
    current_url = url
    current_scheme, current_host, current_port, current_path = scheme, host, port, path
    seen = []

    for _ in range(max_redirects + 1):
        connection = None
        try:
            if current_scheme == "https":
                connection = http.client.HTTPSConnection(
                    current_host, current_port, timeout=timeout, context=context
                )
            else:
                connection = http.client.HTTPConnection(
                    current_host, current_port, timeout=timeout
                )
            connection.request(method.upper(), current_path, body=body, headers=request_headers)
            response = connection.getresponse()
            raw = response.read(max_body)
            text = raw.decode(response.headers.get_content_charset() or "utf-8", "replace")

            merged: Dict[str, str] = {}
            for key, value in response.getheaders():
                lower = key.lower()
                if lower in merged:
                    if value not in merged[lower].split(", "):
                        merged[lower] = f"{merged[lower]}, {value}"
                else:
                    merged[lower] = value

            out["status"] = response.status
            out["reason"] = response.reason
            out["headers"] = merged
            out["body"] = text
            out["server"] = merged.get("server")
            out["ok"] = True
            out["final_url"] = current_url
            out["elapsed_ms"] = int((time.time() - start) * 1000)

            if response.status in (301, 302, 303, 307, 308) and "location" in merged:
                target = merged["location"].strip()
                if not target or target in seen:
                    break
                seen.append(target)
                absolute = urljoin(current_url, target)
                out["redirects"].append({"from": current_url, "to": absolute, "status": response.status})
                next_parsed = urlsplit(absolute)
                if next_parsed.scheme not in ("http", "https") or not next_parsed.hostname:
                    break
                current_url = absolute
                current_scheme = next_parsed.scheme
                current_host = next_parsed.hostname
                current_port = next_parsed.port or (443 if current_scheme == "https" else 80)
                current_path = next_parsed.path or "/"
                if next_parsed.query:
                    current_path = f"{current_path}?{next_parsed.query}"
                if "host" in request_headers:
                    request_headers.pop("host")
                continue
            break
        except ssl.SSLError as exc:
            out["error"] = f"TLS error: {exc}"
            out["ok"] = False
            break
        except socket.timeout:
            out["error"] = "timeout"
            out["ok"] = False
            break
        except (http.client.HTTPException, OSError, ValueError) as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
            out["ok"] = False
            break
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # noqa: BLE001 - close must never mask the real error
                    pass

    out["elapsed_ms"] = out["elapsed_ms"] or int((time.time() - start) * 1000)
    return out


def http_get(url: str, **kwargs: Any) -> Dict[str, Any]:
    return http_request(url, "GET", **kwargs)


def http_head(url: str, **kwargs: Any) -> Dict[str, Any]:
    return http_request(url, "HEAD", **kwargs)


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def fetch_certificate_der(
    host: str, port: int = 443, timeout: float = 8.0
) -> Tuple[Optional[bytes], Optional[ssl.SSLSocket], Optional[str]]:
    """Open a TLS connection and return the peer certificate as DER."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = None
    wrapped = None
    try:
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        wrapped = context.wrap_socket(raw, server_hostname=host)
        return wrapped.getpeercert(binary_form=True), wrapped, None
    except ssl.SSLError as exc:
        return None, None, f"TLS error: {exc}"
    except socket.timeout:
        return None, None, "timeout"
    except (OSError, ValueError) as exc:
        return None, None, f"{type(exc).__name__}: {exc}"
    finally:
        if raw is not None and wrapped is None:
            try:
                raw.close()
            except OSError:
                pass


def _flatten_name(entries: Any) -> Dict[str, str]:
    """``((('commonName','example.com'),),)`` -> ``{'commonName': 'example.com'}``"""
    flat: Dict[str, str] = {}
    if not entries:
        return flat
    for group in entries:
        for pair in group or ():
            if len(pair) == 2:
                key, value = pair
                flat.setdefault(str(key), str(value))
    return flat


def parse_certificate(der: bytes, host: str = "") -> Dict[str, Any]:
    """Decode a DER certificate without any third party library.

    ``getpeercert()`` returns ``{}`` when verification is disabled, so we decode
    the DER through the interpreter's private test decoder when available and
    fall back to an unverified verified-connection probe otherwise.
    """
    info: Dict[str, Any] = {
        "subject": {},
        "issuer": {},
        "subject_alt_names": [],
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "version": None,
        "self_signed": False,
        "decoded": False,
    }
    if not der:
        return info

    decoded: Optional[Dict[str, Any]] = None
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is not None:
        handle = None
        path = None
        try:
            handle, path = tempfile.mkstemp(suffix=".pem")
            with open(path, "wb") as fh:
                fh.write(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
            decoded = decoder(path)
        except Exception:  # noqa: BLE001 - decoder is private API, must not break the audit
            decoded = None
    if not decoded:
        return info

    info["decoded"] = True
    info["subject"] = _flatten_name(decoded.get("subject"))
    info["issuer"] = _flatten_name(decoded.get("issuer"))
    info["not_before"] = decoded.get("notBefore")
    info["not_after"] = decoded.get("notAfter")
    info["serial_number"] = decoded.get("serialNumber")
    info["version"] = decoded.get("version")
    san: List[str] = []
    for kind, value in decoded.get("subjectAltName", ()) or ():
        san.append(f"{kind}:{value}")
    info["subject_alt_names"] = dedupe(san)
    info["self_signed"] = bool(info["subject"]) and info["subject"] == info["issuer"]
    return info


def get_certificate(host: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
    """Fetch and parse the TLS certificate of host:port."""
    der, sock, error = fetch_certificate_der(host, port, timeout)
    result: Dict[str, Any] = {
        "ok": der is not None,
        "host": host,
        "port": port,
        "error": error,
        "protocol": None,
        "cipher": None,
    }
    if sock is not None:
        try:
            result["protocol"] = sock.version()
            cipher = sock.cipher()
            if cipher:
                result["cipher"] = cipher[0]
        except (OSError, ValueError):
            pass
        try:
            sock.close()
        except OSError:
            pass
    if der:
        result.update(parse_certificate(der, host))
    return result


def check_tls_versions(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    """Probe which TLS versions the server accepts.

    Python's ``ssl`` refuses to *enable* TLS 1.0/1.1 on modern OpenSSL builds, so
    a failure to build the context is reported as ``unsupported_locally`` rather
    than as the server rejecting the version — never silently as "disabled".
    """
    versions: Dict[str, Any] = {}
    for label, constant in (
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ):
        if constant is None:
            versions[label] = "unsupported_locally"
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = None
        wrapped = None
        try:
            context.minimum_version = constant
            context.maximum_version = constant
            raw = socket.create_connection((host, int(port)), timeout=timeout)
            wrapped = context.wrap_socket(raw, server_hostname=host)
            versions[label] = True
        except (ssl.SSLError, OSError, ValueError):
            versions[label] = False
        finally:
            if wrapped is not None:
                try:
                    wrapped.close()
                except OSError:
                    pass
            elif raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
    return versions


def http_trace_headers(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Fetch the raw status + headers of *url* for header auditing."""
    result = http_request(url, "GET", timeout=timeout, max_body=4096)
    return {
        "ok": result["ok"],
        "status": result["status"],
        "headers": result["headers"],
        "server": result["server"],
        "error": result["error"],
        "final_url": result["final_url"],
    }
