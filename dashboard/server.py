"""Cyber command-centre dashboard on the standard library HTTP server.

Live data only: every panel reads the local SQLite store and the real system
state. Nothing is mocked. Binding defaults to 127.0.0.1 and the server refuses to
start on a public interface without an explicit ``--allow-public`` flag, because
this dashboard exposes scan history.
"""

from __future__ import annotations

import json
import platform
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from core.config import PROVIDERS, VERSION, Config
from core.db import Database, open_db
from core.utils import now_iso

MAX_BODY = 2 * 1024 * 1024


def system_snapshot(config: Optional[Config] = None, db: Optional[Database] = None) -> Dict[str, Any]:
    """Real local state for the status panel."""
    config = config or Config()
    db = db or open_db()
    stats = db.stats()
    return {
        "app": {"name": "KING REAPER X", "version": VERSION},
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "is_termux": bool(system_snapshot_raw()),
        },
        "time": now_iso(),
        "database": stats,
        "providers": config.provider_report(),
        "providers_configured": len(config.configured_providers()),
        "providers_total": len(PROVIDERS),
        "modules": _module_list(),
        "consent": {"accepted": config.get_bool("consent_accepted", False)},
        "settings": {
            "timeout": config.get("timeout"),
            "threads": config.get("threads"),
            "rate_limit": config.get("rate_limit"),
        },
    }


def _module_list() -> List[Dict[str, Any]]:
    from core import registry

    return [
        {
            "name": item["name"],
            "title": item["title"],
            "description": item["description"],
            "category": item["category"],
            "active": item["active"],
            "requires": list(item["requires"]),
            "importable": item.get("importable", True),
        }
        for item in registry.discover()
    ]


def system_snapshot_raw() -> bool:
    import os

    return "com.termux" in os.environ.get("PREFIX", "") or os.path.exists("/data/data/com.termux")


HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KING REAPER X — Command Centre</title>
<style>
:root{--bg:#080808;--panel:#111;--panel2:#181818;--line:#262626;--red:#FF1010;
      --crimson:#8B0000;--txt:#F2F2F2;--dim:#8E8E8E;--ok:#22C55E;--warn:#F59E0B;--bad:#EF4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
     font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}
a{color:var(--red);text-decoration:none}
.wrap{max-width:1240px;margin:0 auto;padding:26px 20px 70px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;
       border-bottom:2px solid var(--crimson);padding-bottom:16px;margin-bottom:22px;flex-wrap:wrap}
h1{margin:0;font-size:24px;letter-spacing:3px}
h1 span{color:var(--red)}
.tag{color:var(--dim);font-size:11px;letter-spacing:2px;margin-top:6px}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;
      background:var(--panel2);border:1px solid var(--line);font-size:11px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(250px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card h2{margin:0 0 12px;font-size:11px;letter-spacing:2px;text-transform:uppercase;
         color:var(--dim);font-weight:600}
.metric{font-size:30px;font-weight:700;line-height:1}
.metric.small{font-size:19px}
.sub{color:var(--dim);font-size:11px;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:1px;
   border-bottom:1px solid var(--line);padding:7px 8px}
td{padding:8px;border-bottom:1px solid #1a1a1a;vertical-align:top}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;
       letter-spacing:.6px;text-transform:uppercase}
.critical{background:#FF1010;color:#080808}.high{background:#FF4D4D;color:#080808}
.medium{background:#F59E0B;color:#080808}.low{background:#FFD700;color:#080808}
.info{background:#3A3A3A;color:#ddd}
.bar{height:6px;background:#1e1e1e;border-radius:3px;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--crimson),var(--red))}
.sec{margin-top:26px}
.sec h3{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin:0 0 10px}
.mods{display:grid;gap:8px;grid-template-columns:repeat(auto-fill,minmax(215px,1fr))}
.mod{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:10px 12px}
.mod b{font-size:12px}
.mod p{margin:4px 0 0;color:var(--dim);font-size:10.5px;line-height:1.5}
.req{color:var(--warn);font-size:10px}
.empty{color:var(--dim);font-size:12px;padding:10px 0}
footer{margin-top:34px;border-top:1px solid var(--line);padding-top:14px;color:var(--dim);font-size:11px}
button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:8px;
       padding:7px 14px;font-family:inherit;font-size:11px;cursor:pointer}
button:hover{border-color:var(--red)}
</style></head>
<body><div class="wrap">
<header>
  <div><h1>KING <span>REAPER</span> X</h1>
       <div class="tag">ULTIMATE CYBER INTELLIGENCE &amp; SECURITY FRAMEWORK</div></div>
  <div style="text-align:right">
    <div class="pill"><span class="dot"></span><span id="status">live</span></div>
    <div class="sub" id="stamp">loading…</div>
    <div style="margin-top:10px"><button onclick="load()">Refresh</button></div>
  </div>
</header>

<div class="grid" id="top"></div>

<div class="sec">
  <h3>Recent operations</h3>
  <div class="card"><div id="scans"></div></div>
</div>

<div class="sec">
  <h3>Modules</h3>
  <div class="card"><div class="mods" id="mods"></div></div>
</div>

<div class="sec">
  <h3>API providers</h3>
  <div class="card"><div id="providers"></div></div>
</div>

<div class="sec">
  <h3>Audit trail</h3>
  <div class="card"><div id="audit"></div></div>
</div>

<footer>
  Local-only by default (127.0.0.1). Collection uses public, authorized or consented
  sources only. <span id="ver"></span>
</footer>
</div>
<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sev = s => `<span class="badge ${esc(String(s||'info').toLowerCase())}">${esc(s||'info')}</span>`;

async function get(url){ const r = await fetch(url); if(!r.ok) throw new Error(r.status); return r.json(); }

function card(title, value, sub, small){
  return `<div class="card"><h2>${esc(title)}</h2>
    <div class="metric ${small?'small':''}">${value}</div>
    <div class="sub">${esc(sub||'')}</div></div>`;
}

async function load(){
  try{
    const [sys, hist, prov, audit] = await Promise.all([
      get('/api/system'), get('/api/history?limit=8'), get('/api/providers'), get('/api/audit?limit=8')
    ]);
    document.getElementById('stamp').textContent = sys.time;
    document.getElementById('ver').textContent = sys.app.name + ' v' + sys.app.version;

    const db = sys.database || {};
    const sev = db.by_severity || {};
    const crit = (sev.critical||0), high = (sev.high||0);
    document.getElementById('top').innerHTML =
      card('Operations logged', db.total_scans ?? 0, (db.by_module||[]).map(m=>`${m.module}:${m.count}`).join('  ') || 'none yet')
      + card('Provider keys', `${sys.providers_configured}/${sys.providers_total}`,
             sys.providers_configured ? 'configured' : 'none — modules run in degraded mode')
      + card('Findings', `${crit} critical · ${high} high`,
             Object.entries(sev).map(([k,v])=>`${k}:${v}`).join('  ') || 'no findings yet', true)
      + card('Host', esc(sys.host.machine), `${esc(sys.host.platform)} · py${esc(sys.host.python)}`, true)
      + card('Modules loaded', (sys.modules||[]).filter(m=>m.importable).length,
             `${(sys.modules||[]).filter(m=>m.active).length} require --authorized`, true)
      + card('Consent', sys.consent?.accepted ? 'accepted' : 'pending',
             sys.consent?.accepted ? 'terms on file' : 'run any command to accept', true);

    const rows = (hist.scans||[]);
    document.getElementById('scans').innerHTML = rows.length ? `<table>
      <thead><tr><th>#</th><th>Module</th><th>Target</th><th>Risk</th><th>Score</th><th>When</th></tr></thead>
      <tbody>${rows.map(s=>`<tr><td>${s.id}</td><td>${esc(s.module)}</td><td>${esc(s.target)}</td>
        <td>${sev_risk(s)}</td><td>${esc(s.score ?? '-')}</td><td>${esc(s.created_at)}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No operations recorded yet. Run a module and refresh.</div>';

    function sev_risk(s){
      if(s.status !== 'ok') return `<span class="badge info">failed</span>`;
      return `<span class="badge ${esc(s.risk||'info')}">${esc(s.risk||'info')}</span>`;
    }

    const mods = (sys.modules||[]);
    document.getElementById('mods').innerHTML = mods.map(m=>`
      <div class="mod"><b>${esc(m.title)}</b>
        <p>${esc(m.description)}</p>
        ${m.active?'<p class="req">requires --authorized</p>':''}
        ${(m.requires||[]).length?`<p class="req">needs ${esc(m.requires.join(', '))}</p>`:''}
      </div>`).join('') || '<div class="empty">No modules discovered.</div>';

    const ps = (prov.providers||[]);
    document.getElementById('providers').innerHTML = `<table>
      <thead><tr><th>Provider</th><th>State</th><th>Env var</th><th>Purpose</th></tr></thead>
      <tbody>${ps.map(p=>`<tr><td>${esc(p.provider)}</td>
        <td><span class="badge ${p.configured?'low':'info'}">${p.configured?esc(p.source||'set'):'not set'}</span></td>
        <td>${esc(p.env_var)}</td><td style="color:#8E8E8E">${esc(p.purpose)}</td></tr>`).join('')}
      </tbody></table>`;

    const au = (audit.entries||[]);
    document.getElementById('audit').innerHTML = au.length ? `<table>
      <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
      <tbody>${au.map(a=>`<tr><td>${esc(a.created_at)}</td><td>${esc(a.action)}</td>
        <td>${esc(a.target||'-')}</td><td style="color:#8E8E8E">${esc(a.detail||'')}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No audit entries yet.</div>';

    document.getElementById('status').textContent = 'live';
  }catch(e){
    document.getElementById('status').textContent = 'offline: ' + e.message;
  }
}
load(); setInterval(load, 15000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"KingReaperX/{VERSION}"
    sys_version = ""

    db: Database
    config: Config
    quiet: bool = True

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib signature
        if not self.quiet:
            sys.stderr.write(f"[dashboard] {self.address_string()} {fmt % args}\n")

    # -- helpers ----------------------------------------------------------- #
    def _send(self, body: bytes, status: int = 200, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(json.dumps(payload, default=str).encode(), status)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json({"ok": False, "error": code, "message": message}, status)

    # -- routes ------------------------------------------------------------ #
    def do_HEAD(self) -> None:  # noqa: N802 - stdlib naming
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parts = urlsplit(self.path)
        route = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)

        try:
            if route in ("/", "/index.html"):
                self._send(HTML.encode(), content_type="text/html; charset=utf-8")
                return
            if route == "/api/system":
                self._json(system_snapshot(self.config, self.db))
                return
            if route == "/api/history":
                limit = _int_param(query, "limit", 25, 1, 200)
                module = (query.get("module") or [None])[0]
                self._json({"ok": True, "scans": self.db.recent_scans(limit=limit, module=module)})
                return
            if route == "/api/stats":
                self._json({"ok": True, **self.db.stats()})
                return
            if route == "/api/providers":
                self._json({"ok": True, "providers": self.config.provider_report()})
                return
            if route == "/api/audit":
                limit = _int_param(query, "limit", 50, 1, 500)
                self._json({"ok": True, "entries": self.db.audit_log(limit=limit)})
                return
            if route == "/api/assets":
                target = (query.get("target") or [None])[0] or None
                self._json({"ok": True, "assets": self.db.assets(target=target)})
                return
            if route.startswith("/api/scan/"):
                raw = route.rsplit("/", 1)[-1]
                if not raw.isdigit():
                    self._error(400, "bad_id", "Scan id must be numeric.")
                    return
                scan = self.db.get_scan(int(raw))
                if scan is None:
                    self._error(404, "not_found", f"No scan with id {raw}.")
                    return
                self._json({"ok": True, "scan": scan})
                return
            if route == "/healthz":
                self._json({"ok": True, "time": now_iso(), "version": VERSION})
                return
            self._error(404, "not_found", f"No route for {route}")
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 - a dashboard must never die on one bad request
            self._error(500, "internal_error", f"{type(exc).__name__}: {exc}")


def _int_param(query: Dict[str, List[str]], name: str, default: int, low: int, high: int) -> int:
    raw = (query.get(name) or [str(default)])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def create_server(
    host: str = "127.0.0.1",
    port: int = 8899,
    config: Optional[Config] = None,
    db: Optional[Database] = None,
    allow_public: bool = False,
    quiet: bool = True,
) -> ThreadingHTTPServer:
    config = config or Config()
    db = db or open_db()
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_public:
        raise ValueError(
            f"Refusing to bind the dashboard to {host}: it exposes scan history. "
            "Pass allow_public=True / --allow-public if you really mean it."
        )
    handler = type(
        "BoundHandler",
        (Handler,),
        {"db": db, "config": config, "quiet": quiet},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(
    host: str = "127.0.0.1",
    port: int = 8899,
    config: Optional[Config] = None,
    allow_public: bool = False,
    quiet: bool = True,
    block: bool = True,
) -> Tuple[ThreadingHTTPServer, threading.Thread]:
    server = create_server(host, port, config=config, allow_public=allow_public, quiet=quiet)
    thread = threading.Thread(target=server.serve_forever, name="reaper-dashboard", daemon=True)
    thread.start()
    if block:
        try:
            while thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
    return server, thread
