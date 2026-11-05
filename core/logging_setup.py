"""Rotating file + console logging with secret redaction.

Every log record passes through :func:`redact` so an API key can never end up in
``~/.kingreaperx/logs`` even when a provider echoes it back in an error.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path
from typing import Optional

from .config import LOG_DIR, ensure_dirs

REDACTIONS = [
    (re.compile(r"(sk-[A-Za-z0-9_\-]{8,})"), "sk-***"),
    (re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)([A-Za-z0-9_\-]{8,})"), r"\1***"),
    (re.compile(r"(?i)(authorization\"?\s*[:=]\s*\"?bearer\s+)([A-Za-z0-9._\-]{8,})"), r"\1***"),
    (re.compile(r"(?i)(x-apikey\"?\s*[:=]\s*\"?)([A-Za-z0-9]{8,})"), r"\1***"),
    (re.compile(r"(?i)(token\"?\s*[:=]\s*\"?)([A-Za-z0-9._\-]{12,})"), r"\1***"),
]

_LOGGER_NAME = "kingreaperx"
_configured = False


def redact(text: object, extra_secrets: Optional[list] = None) -> str:
    value = "" if text is None else str(text)
    for pattern, replacement in REDACTIONS:
        value = pattern.sub(replacement, value)
    for secret in extra_secrets or []:
        if secret and len(str(secret)) >= 8:
            value = value.replace(str(secret), "***")
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - stdlib signature
        record.msg = redact(record.msg)
        if record.args:
            try:
                record.args = tuple(redact(arg) for arg in record.args) if isinstance(record.args, tuple) else record.args
            except (TypeError, ValueError):
                record.args = ()
        return True


def get_logger(name: str = "") -> logging.Logger:
    """Return the framework logger (configured once)."""
    global _configured
    logger = logging.getLogger(f"{_LOGGER_NAME}.{name}" if name else _LOGGER_NAME)
    if _configured:
        return logger
    ensure_dirs()
    root = logging.getLogger(_LOGGER_NAME)
    root.setLevel(logging.INFO)
    root.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    )
    filter_ = RedactingFilter()

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(Path(LOG_DIR) / "reaper.log"), maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(filter_)
        file_handler.setLevel(logging.DEBUG)
        root.addHandler(file_handler)
    except OSError:
        pass

    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter("%(message)s"))
    stream.addFilter(filter_)
    stream.setLevel(logging.WARNING)
    root.addHandler(stream)

    _configured = True
    return logger


def log_path() -> Path:
    return Path(LOG_DIR) / "reaper.log"


class AuditLogger:
    """Writes both to the SQLite audit table and to the log file."""

    def __init__(self, db=None, name: str = "audit") -> None:
        self.db = db
        self.logger = get_logger(name)

    def log(self, action: str, target: str = "", detail: str = "", actor: str = "") -> None:
        message = f"{action} target={target or '-'} {detail}".strip()
        self.logger.info(redact(message))
        if self.db is not None:
            try:
                self.db.audit(action, target=target, detail=detail, actor=actor)
            except Exception:  # noqa: BLE001 - audit must never break a scan
                pass
