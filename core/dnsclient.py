"""Minimal DNS client built on the wire protocol (no dnspython dependency).

Supports A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR and SRV over UDP with a
TCP fallback when the answer is truncated. Used by the reconnaissance and
threat intelligence modules so the framework needs no third party resolver.
"""

from __future__ import annotations

import random
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from .utils import is_ip

TYPE_NAMES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA",
}
NAME_TYPES: Dict[str, int] = {value: key for key, value in TYPE_NAMES.items()}

CLASS_IN = 1
RCODE_TEXT: Dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


class DnsError(Exception):
    """Raised when a query could not be performed at all (not for NXDOMAIN)."""


def _encode_name(name: str) -> bytes:
    cleaned = (name or "").strip().rstrip(".")
    if not cleaned:
        return b"\x00"
    parts = cleaned.split(".")
    out = b""
    for part in parts:
        raw = part.encode("idna") if any(ord(ch) > 127 for ch in part) else part.encode("ascii")
        if len(raw) > 63:
            raise DnsError(f"label longer than 63 bytes: {part!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """Decode a (possibly compressed) domain name."""
    if depth > 12:
        raise DnsError("compression pointer loop")
    labels: List[str] = []
    position = offset
    jumped = False
    end_offset = offset
    while True:
        if position >= len(data):
            raise DnsError("name runs past packet end")
        length = data[position]
        if length == 0:
            position += 1
            if not jumped:
                end_offset = position
            break
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(data):
                raise DnsError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[position + 1]
            if not jumped:
                end_offset = position + 2
            jumped = True
            position = pointer
            continue
        position += 1
        labels.append(data[position : position + length].decode("ascii", "replace"))
        position += length
        if not jumped:
            end_offset = position
    return ".".join(labels), end_offset


def _build_query(domain: str, record_type: str, query_id: int) -> bytes:
    qtype = NAME_TYPES.get(record_type.upper())
    if qtype is None:
        raise DnsError(f"unsupported record type: {record_type}")
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(domain) + struct.pack("!HH", qtype, CLASS_IN)


def _parse_response(data: bytes, query_id: int) -> Dict[str, Any]:
    if len(data) < 12:
        raise DnsError("response shorter than DNS header")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise DnsError("transaction id mismatch")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    result: Dict[str, Any] = {
        "rcode": rcode,
        "rcode_text": RCODE_TEXT.get(rcode, f"RCODE{rcode}"),
        "truncated": truncated,
        "authoritative": bool(flags & 0x0400),
        "answers": [],
        "authority": [],
        "additional": [],
    }

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4

    def read_records(count: int) -> List[Dict[str, Any]]:
        nonlocal offset
        records: List[Dict[str, Any]] = []
        for _ in range(count):
            name, offset_after_name = _decode_name(data, offset)
            offset = offset_after_name
            if offset + 10 > len(data):
                raise DnsError("truncated resource record")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_start = offset
            rdata = data[rdata_start : rdata_start + rdlength]
            if len(rdata) < rdlength:
                raise DnsError("truncated rdata")
            offset = rdata_start + rdlength
            record: Dict[str, Any] = {
                "name": name,
                "record_type": TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                "type_code": rtype,
                "class": "IN" if rclass == CLASS_IN else str(rclass),
                "ttl": ttl,
                "value": None,
            }
            try:
                record["value"] = _parse_rdata(rdata, rtype, data, rdata_start)
            except DnsError:
                record["value"] = rdata.hex()
            records.append(record)
        return records

    result["answers"] = read_records(ancount)
    result["authority"] = read_records(nscount)
    result["additional"] = read_records(arcount)
    return result


def _parse_rdata(rdata: bytes, rtype: int, packet: bytes, rdata_start: int) -> Any:
    if rtype == 1 and len(rdata) == 4:
        return ".".join(str(b) for b in rdata)
    if rtype == 28 and len(rdata) == 16:
        import ipaddress

        return str(ipaddress.IPv6Address(rdata))
    if rtype in (2, 5, 12):
        name, _ = _decode_name(packet, rdata_start)
        return name
    if rtype == 15:
        if len(rdata) < 3:
            raise DnsError("short MX rdata")
        priority = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _decode_name(packet, rdata_start + 2)
        return f"{priority} {exchange}"
    if rtype == 16:
        parts: List[str] = []
        index = 0
        while index < len(rdata):
            length = rdata[index]
            index += 1
            parts.append(rdata[index : index + length].decode("utf-8", "replace"))
            index += length
        return " ".join(parts)
    if rtype == 6:
        mname, after = _decode_name(packet, rdata_start)
        rname, after = _decode_name(packet, after)
        if after + 20 > len(packet):
            raise DnsError("short SOA rdata")
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", packet[after : after + 20])
        return {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    if rtype == 33:
        if len(rdata) < 7:
            raise DnsError("short SRV rdata")
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = _decode_name(packet, rdata_start + 6)
        return f"{priority} {weight} {port} {target}"
    if rtype == 257:
        if len(rdata) < 2:
            raise DnsError("short CAA rdata")
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2 : 2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len :].decode("utf-8", "replace")
        return f"{flags} {tag} \"{value}\""
    return rdata.hex()


def _query_udp(payload: bytes, server: str, port: int, timeout: float, query_id: int) -> bytes:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (server, port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout as exc:
        raise DnsError("timeout") from exc
    except OSError as exc:
        raise DnsError(str(exc)) from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _query_tcp(payload: bytes, server: str, port: int, timeout: float) -> bytes:
    sock = None
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        header = _recv_exact(sock, 2)
        length = struct.unpack("!H", header)[0]
        return _recv_exact(sock, length)
    except socket.timeout as exc:
        raise DnsError("timeout") from exc
    except OSError as exc:
        raise DnsError(str(exc)) from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = b""
    while len(chunks) < count:
        piece = sock.recv(count - len(chunks))
        if not piece:
            raise DnsError("connection closed early")
        chunks += piece
    return chunks


def resolve(
    domain: str,
    record_type: str = "A",
    server: Optional[str] = None,
    timeout: float = 5.0,
    use_tcp: bool = False,
) -> Dict[str, Any]:
    """Query *domain* for *record_type*.

    Returns ``{ok, domain, record_type, status, answers, ...}``. A missing record
    is ``ok: True`` with ``status: NXDOMAIN`` — that is a valid answer, not an
    error, and the distinction matters for the callers.
    """
    domain = (domain or "").strip()
    rtype = (record_type or "A").strip().upper()
    result: Dict[str, Any] = {
        "ok": False,
        "domain": domain,
        "record_type": rtype,
        "server": server or "system",
        "status": None,
        "answers": [],
        "authority": [],
        "additional": [],
        "truncated": False,
        "authoritative": False,
        "elapsed_ms": 0,
        "error": None,
    }
    if not domain:
        result["error"] = "empty domain"
        return result
    if rtype not in NAME_TYPES:
        result["error"] = f"unsupported record type: {rtype}"
        return result

    servers: List[str] = []
    if server:
        servers = [server]
    else:
        servers = _system_resolvers()
    if not servers:
        servers = ["1.1.1.1"]

    start = time.time()
    last_error = "no resolver answered"
    for candidate in servers:
        for transport in (("tcp",) if use_tcp else ("udp", "tcp")):
            query_id = random.randint(0, 0xFFFF)
            try:
                payload = _build_query(domain, rtype, query_id)
                if transport == "udp":
                    raw = _query_udp(payload, candidate, 53, timeout, query_id)
                    if len(raw) >= 3 and raw[2] & 0x02:
                        raw = _query_tcp(payload, candidate, 53, timeout)
                else:
                    raw = _query_tcp(payload, candidate, 53, timeout)
                parsed = _parse_response(raw, query_id)
            except DnsError as exc:
                last_error = str(exc)
                continue

            result.update(parsed)
            result["ok"] = True
            result["server"] = candidate
            result["status"] = parsed["rcode_text"]
            result["elapsed_ms"] = int((time.time() - start) * 1000)
            result["error"] = None
            return result

    result["error"] = last_error
    result["elapsed_ms"] = int((time.time() - start) * 1000)
    return result


def _system_resolvers() -> List[str]:
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2 and is_ip(parts[1]):
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def resolve_all(
    domain: str, server: Optional[str] = None, timeout: float = 5.0,
    types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Resolve several record types and group them by type."""
    wanted = types or ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for rtype in wanted:
        response = resolve(domain, rtype, server=server, timeout=timeout)
        if response["ok"]:
            grouped[rtype] = response["answers"]
        else:
            errors[rtype] = response["error"] or "unknown"
    return {
        "ok": True,
        "domain": domain,
        "records": grouped,
        "errors": errors,
        "types_resolved": sorted(grouped.keys()),
    }


def reverse_lookup(ip: str, timeout: float = 5.0) -> Dict[str, Any]:
    """PTR lookup for an address."""
    if not is_ip(ip):
        return {"ok": False, "error": "not_an_ip", "ip": ip, "names": []}
    import ipaddress

    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        query = ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa"
    else:
        query = ".".join(reversed(f"{addr.exploded.replace(':', '')}")) + ".ip6.arpa"
    response = resolve(query, "PTR", timeout=timeout)
    names = [entry["value"] for entry in response.get("answers", []) if entry.get("value")]
    return {
        "ok": response["ok"],
        "ip": ip,
        "query": query,
        "names": names,
        "status": response.get("status"),
        "error": response.get("error"),
    }
