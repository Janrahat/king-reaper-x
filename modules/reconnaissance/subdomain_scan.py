"""Subdomain discovery from public sources, plus optional DNS brute force.

Two clearly separated modes:

* **Passive** (default) — certificate transparency logs from crt.sh and the
  public ``hackertarget`` host-search feed. Reads only data the owners already
  published; requires no authorization because nothing is sent to the target.
* **Active** — DNS brute force against the target's nameservers using the
  bundled wordlist. Requires ``authorized=True``.

Every candidate is confirmed with a real DNS resolution, so a name that appears
in a CT log but no longer resolves is reported as ``historical``, not as a live
subdomain.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from core import dnsclient
from core.config import DATA_DIR, Config
from core.utils import dedupe, now_iso, resolve_host, run_threaded

NAME = "subdomains"
TITLE = "Subdomain Discovery"
DESCRIPTION = "Enumerate subdomains passively via certificate transparency, optionally brute force (authorized)"
CATEGORY = "recon"
ACTIVE = False  # the default passive mode is; brute force demands its own flag
REQUIRES: Tuple[str, ...] = ()

WORDLIST = DATA_DIR / "subdomains.txt"
CRT_SH = "https://crt.sh/?q=%25.{domain}&output=json"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/?q={domain}"


def _load_wordlist(path: Optional[Any] = None) -> List[str]:
    target = path or WORDLIST
    entries: List[str] = []
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                if re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", line):
                    entries.append(line)
    except OSError:
        return []
    return dedupe(entries)


def from_crt_sh(domain: str, timeout: float = 20.0) -> Dict[str, Any]:
    """Parse certificate transparency JSON for every name ever issued."""
    from core.net import http_request

    response = http_request(
        CRT_SH.format(domain=domain), timeout=timeout, max_body=8 * 1024 * 1024
    )
    if not response["ok"]:
        return {"ok": False, "source": "crt.sh", "names": [], "error": response.get("error")}
    try:
        rows = json.loads(response.get("body") or "[]")
    except ValueError:
        body = (response.get("body") or "")[:200]
        return {
            "ok": False,
            "source": "crt.sh",
            "names": [],
            "error": "non_json_response",
            "detail": body,
        }
    if not isinstance(rows, list):
        return {"ok": False, "source": "crt.sh", "names": [], "error": "unexpected_payload"}

    found: Set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            for name in str(row.get(field) or "").splitlines():
                candidate = name.strip().lower().lstrip("*.").rstrip(".")
                if candidate.endswith("." + domain) or candidate == domain:
                    found.add(candidate)
    return {"ok": True, "source": "crt.sh", "names": sorted(found), "error": None}


def from_hackertarget(domain: str, timeout: float = 15.0) -> Dict[str, Any]:
    """Public host-search feed. Returns ``[]`` when the quota is exhausted."""
    from core.net import http_request

    response = http_request(HACKERTARGET.format(domain=domain), timeout=timeout)
    if not response["ok"]:
        return {"ok": False, "source": "hackertarget", "names": [], "error": response.get("error")}
    body = (response.get("body") or "").strip()
    if body.lower().startswith("error") or "api count exceeded" in body.lower():
        return {
            "ok": False,
            "source": "hackertarget",
            "names": [],
            "error": "quota_or_error",
            "detail": body[:150],
        }
    names: Set[str] = set()
    for line in body.splitlines():
        host = line.split(",")[0].strip().lower().rstrip(".")
        if host.endswith("." + domain):
            names.add(host)
    return {"ok": True, "source": "hackertarget", "names": sorted(names), "error": None}


def brute_force(
    domain: str, words: List[str], threads: int = 20, timeout: float = 3.0
) -> Dict[str, Any]:
    candidates = [f"{word}.{domain}" for word in words]

    def probe(candidate: str) -> Optional[List[str]]:
        addresses = resolve_host(candidate, timeout=timeout)
        return addresses or None

    hits: List[Dict[str, Any]] = []
    for candidate, value, _error in run_threaded(probe, candidates, threads=threads):
        if value:
            hits.append({"host": candidate, "addresses": value})
    return {"ok": True, "tested": len(candidates), "hits": hits}


def discover(
    domain: str,
    config: Optional[Config] = None,
    authorized: bool = False,
    brute: bool = False,
    words: Optional[List[str]] = None,
    threads: int = 20,
    timeout: float = 5.0,
    max_hosts: int = 2000,
    verify: bool = True,
) -> Dict[str, Any]:
    config = config or Config()
    result: Dict[str, Any] = {
        "ok": False,
        "module": NAME,
        "target": domain,
        "queried_at": now_iso(),
        "findings": [],
        "sources": {},
        "live": [],
        "historical": [],
    }
    name = (domain or "").strip().lower().rstrip(".")
    if not name or "." not in name:
        result.update({"error": "not_a_domain", "message": f"'{domain}' is not a valid domain."})
        return result

    found: Set[str] = {name}

    for source_func in (from_crt_sh, from_hackertarget):
        try:
            outcome = source_func(name)
        except Exception as exc:  # noqa: BLE001 - one dead source must not stop discovery
            outcome = {"ok": False, "source": source_func.__name__, "names": [], "error": str(exc)}
        result["sources"][outcome.get("source", "unknown")] = {
            "ok": outcome.get("ok"),
            "count": len(outcome.get("names") or []),
            "error": outcome.get("error"),
        }
        found.update(outcome.get("names") or [])

    if brute:
        if not authorized:
            result["brute_force"] = {
                "ok": False,
                "skipped": True,
                "error": "authorization_required",
                "message": "DNS brute force sends packets derived from the target's zone; re-run with --authorized.",
            }
        else:
            wordlist = words or _load_wordlist()
            if not wordlist:
                result["brute_force"] = {
                    "ok": False,
                    "error": "missing_wordlist",
                    "message": f"No wordlist at {WORDLIST}. Run `python main.py tools` to check data files.",
                }
            else:
                outcome = brute_force(name, wordlist, threads=threads, timeout=min(timeout, 4.0))
                found.update(hit["host"] for hit in outcome["hits"])
                result["brute_force"] = {
                    "ok": True,
                    "tested": outcome["tested"],
                    "hits": len(outcome["hits"]),
                    "wordlist_size": len(wordlist),
                }

    candidates = sorted(found)[: max(1, max_hosts)]

    if verify:
        def check(host: str) -> Optional[List[str]]:
            return resolve_host(host, timeout=min(timeout, 4.0)) or None

        for host, value, _error in run_threaded(check, candidates, threads=threads):
            if value:
                result["live"].append({"host": host, "addresses": value})
            elif host != name:
                result["historical"].append({"host": host, "note": "in CT logs, no current DNS answer"})
    else:
        result["live"] = [{"host": host, "addresses": []} for host in candidates]

    result["ok"] = True
    result["total_candidates"] = len(found)
    live_count = len(result["live"])
    result["summary"] = (
        f"{name}: {live_count} live subdomain(s), "
        f"{len(result['historical'])} historical name(s) across {len(result['sources'])} source(s)"
    )
    result["risk"] = "info"
    result["score"] = 0

    interesting = [
        host for host in result["live"]
        if any(
            marker in host["host"].split(".")[0]
            for marker in ("dev", "staging", "test", "admin", "internal", "jenkins", "git", "db", "backup")
        )
    ]
    for entry in interesting:
        result["findings"].append(
            {
                "severity": "low",
                "title": f"Potentially sensitive hostname: {entry['host']}",
                "detail": "Development, admin or infrastructure names are frequently less hardened than production.",
            }
        )
    return result


def run(target: str, config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return discover(
        target,
        config=config,
        authorized=bool(options.get("authorized", False)),
        brute=bool(options.get("brute", False)),
        words=options.get("words"),
        threads=int(options.get("threads", 20) or 20),
        timeout=float(options.get("timeout", 5.0) or 5.0),
        max_hosts=int(options.get("max_hosts", 2000) or 2000),
    )
