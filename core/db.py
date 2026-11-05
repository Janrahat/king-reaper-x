"""SQLite persistence for scan history, findings and audit logs.

Single module, standard library only. Every write goes through :meth:`Database.record`
so the dashboard, the report generator and the audit trail always see the same
row shape.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import DB_FILE, ensure_dirs
from .utils import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    module        TEXT NOT NULL,
    target        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'ok',
    risk          TEXT,
    score         INTEGER,
    summary       TEXT,
    duration_ms   INTEGER,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_module  ON scans(module);
CREATE INDEX IF NOT EXISTS idx_scans_target  ON scans(target);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    reference   TEXT,
    created_at  TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    payload    TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    actor      TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at DESC);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(target, kind, value)
);
"""


class Database:
    """Thread-safe wrapper around sqlite3 (one connection per thread)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else DB_FILE
        self._local = threading.local()
        self._lock = threading.Lock()
        ensure_dirs()
        self._init_schema()

    # -- connection -------------------------------------------------------- #
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=15.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._conn()
            conn.executescript(SCHEMA)
            conn.commit()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    @contextmanager
    def transaction(self):
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # -- writes ------------------------------------------------------------ #
    def record(
        self,
        module: str,
        target: str,
        result: Dict[str, Any],
        duration_ms: Optional[int] = None,
        findings: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> int:
        """Persist one module run and return the scan id."""
        created = now_iso()
        status = "ok" if result.get("ok") else "error"
        risk = result.get("risk")
        score = result.get("score")
        summary = result.get("summary") or result.get("error") or ""
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (module, target, status, risk, score, summary, duration_ms, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (module, target, status, risk, score, str(summary)[:500], duration_ms, created),
            )
            scan_id = int(cursor.lastrowid)
            conn.execute(
                "INSERT INTO results (scan_id, payload) VALUES (?,?)",
                (scan_id, json.dumps(result, default=str)),
            )
            rows = list(findings or result.get("findings") or [])
            for finding in rows:
                conn.execute(
                    "INSERT INTO findings (scan_id, severity, title, detail, reference, created_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        scan_id,
                        str(finding.get("severity", "info")).lower(),
                        str(finding.get("title", ""))[:200],
                        str(finding.get("detail", ""))[:2000],
                        str(finding.get("reference", ""))[:300] or None,
                        created,
                    ),
                )
        return scan_id

    def audit(self, action: str, target: str = "", detail: str = "", actor: str = "") -> None:
        try:
            with self.transaction() as conn:
                conn.execute(
                    "INSERT INTO audit (action, target, detail, actor, created_at) VALUES (?,?,?,?,?)",
                    (action, target, str(detail)[:1000], actor, now_iso()),
                )
        except sqlite3.Error:
            pass

    def remember_asset(self, target: str, kind: str, value: str) -> None:
        stamp = now_iso()
        try:
            with self.transaction() as conn:
                conn.execute(
                    "INSERT INTO assets (target, kind, value, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?)"
                    " ON CONFLICT(target, kind, value) DO UPDATE SET last_seen=excluded.last_seen",
                    (target, kind, str(value)[:500], stamp, stamp),
                )
        except sqlite3.Error:
            pass

    def clear(self) -> None:
        with self.transaction() as conn:
            for table in ("findings", "results", "scans", "audit", "assets"):
                conn.execute(f"DELETE FROM {table}")

    # -- reads ------------------------------------------------------------- #
    def recent_scans(self, limit: int = 25, module: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM scans"
        params: List[Any] = []
        if module:
            query += " WHERE module = ?"
            params.append(module)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        conn = self._conn()
        return [dict(row) for row in conn.execute(query, params).fetchall()]

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = dict(row)
        payload_row = conn.execute(
            "SELECT payload FROM results WHERE scan_id = ? ORDER BY id DESC LIMIT 1", (scan_id,)
        ).fetchone()
        scan["payload"] = json.loads(payload_row["payload"]) if payload_row else None
        scan["findings"] = [
            dict(item)
            for item in conn.execute(
                "SELECT severity, title, detail, reference FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        return scan

    def stats(self) -> Dict[str, Any]:
        conn = self._conn()
        total = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        by_module = [
            dict(row)
            for row in conn.execute(
                "SELECT module, COUNT(*) AS count FROM scans GROUP BY module ORDER BY count DESC"
            ).fetchall()
        ]
        by_severity = {
            row["severity"]: row["count"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"
            ).fetchall()
        }
        by_risk = {
            row["risk"]: row["count"]
            for row in conn.execute(
                "SELECT risk, COUNT(*) AS count FROM scans WHERE risk IS NOT NULL GROUP BY risk"
            ).fetchall()
        }
        latest = conn.execute("SELECT created_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "total_scans": total,
            "by_module": by_module,
            "by_severity": by_severity,
            "by_risk": by_risk,
            "last_scan": latest["created_at"] if latest else None,
            "db_path": str(self.path),
            "db_size": self.path.stat().st_size if self.path.exists() else 0,
        }

    def severity_counts(self, scan_id: int) -> Dict[str, int]:
        conn = self._conn()
        return {
            row["severity"]: row["count"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity",
                (scan_id,),
            ).fetchall()
        }

    def audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._conn()
        return [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        ]

    def assets(self, target: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._conn()
        if target:
            rows = conn.execute(
                "SELECT * FROM assets WHERE target = ? ORDER BY last_seen DESC LIMIT ?",
                (target, int(limit)),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(row) for row in rows]


def open_db(path: Optional[Path] = None) -> Database:
    return Database(path=path)
