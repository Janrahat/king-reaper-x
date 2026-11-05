"""Configuration and credential storage.

Rules enforced here:

* Environment variables always win over the on-disk file.
* Keys are never written to the repository, never logged, never printed in
  full. The on-disk store is ``~/.kingreaperx/config.json`` at mode ``0600``.
* Every optional provider is described by a :class:`ProviderSpec`, so a missing
  key produces a precise instruction instead of a traceback.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_NAME = "kingreaperx"
APP_TITLE = "KING REAPER X"
VERSION = "2.0.0"

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Default locations; every one can be overridden by an environment variable.
HOME = Path(os.path.expanduser("~"))
CONFIG_DIR = Path(os.environ.get("REAPER_CONFIG_DIR") or (HOME / f".{APP_NAME}"))
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_FILE = Path(os.environ.get("REAPER_DB_PATH") or (CONFIG_DIR / "reaper.db"))
LOG_DIR = Path(os.environ.get("REAPER_LOG_DIR") or (CONFIG_DIR / "logs"))
REPORT_DIR = Path(os.environ.get("REAPER_REPORT_DIR") or (REPO_ROOT / "reports"))
DATA_DIR = REPO_ROOT / "data"


@dataclass(frozen=True)
class ProviderSpec:
    """An optional third party data source.

    ``env_var`` is the preferred way to supply the credential; ``secret_name``
    is the key used in the local config store.
    """

    name: str
    env_var: str
    purpose: str
    signup: str = ""
    free_tier: str = ""


PROVIDERS: Dict[str, ProviderSpec] = {
    spec.name: spec
    for spec in (
        ProviderSpec(
            name="virustotal",
            env_var="VIRUSTOTAL_API_KEY",
            purpose="Domain/IP/URL reputation and public breach-of-reputation signals",
            signup="https://www.virustotal.com/gui/join-us",
            free_tier="4 requests/minute, 500/day",
        ),
        ProviderSpec(
            name="abuseipdb",
            env_var="ABUSEIPDB_API_KEY",
            purpose="Public IP abuse reputation reports",
            signup="https://www.abuseipdb.com/account/api",
            free_tier="1000 checks/day",
        ),
        ProviderSpec(
            name="shodan",
            env_var="SHODAN_API_KEY",
            purpose="Public host exposure metadata (banners for your own assets)",
            signup="https://account.shodan.io/register",
            free_tier="Limited, paid for host lookups",
        ),
        ProviderSpec(
            name="hibp",
            env_var="HIBP_API_KEY",
            purpose="Authorized email breach exposure checks (Have I Been Pwned)",
            signup="https://haveibeenpwned.com/API/Key",
            free_tier="Paid API key",
        ),
        ProviderSpec(
            name="numverify",
            env_var="NUMVERIFY_API_KEY",
            purpose="Phone number carrier / line type enrichment",
            signup="https://numverify.com/product",
            free_tier="100 requests/month",
        ),
        ProviderSpec(
            name="ipinfo",
            env_var="IPINFO_TOKEN",
            purpose="Higher accuracy IP geolocation and ASN data",
            signup="https://ipinfo.io/signup",
            free_tier="50k requests/month",
        ),
        ProviderSpec(
            name="whatsapp_token",
            env_var="WHATSAPP_BUSINESS_TOKEN",
            purpose="Official WhatsApp Business Cloud API business profile lookups",
            signup="https://developers.facebook.com/docs/whatsapp/cloud-api",
            free_tier="Per Meta pricing",
        ),
    )
}


DEFAULT_SETTINGS: Dict[str, Any] = {
    "timeout": 8,
    "threads": 16,
    "rate_limit": 8.0,
    "user_agent": "KING-REAPER-X/2.0 security-assessment",
    "color": True,
    "animations": True,
    "consent_accepted": False,
    "consent_version": 1,
    "dashboard_host": "127.0.0.1",
    "dashboard_port": 8899,
    "telemetry": False,
    "max_hosts_subdomain": 2000,
    "port_scan_default": "top",
}


def ensure_dirs() -> None:
    for path in (CONFIG_DIR, LOG_DIR, REPORT_DIR):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory so a crash cannot truncate
    an existing config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = None
    temp_path = None
    try:
        handle, temp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            handle = None
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if handle is not None:
            os.close(handle)
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


class Config:
    """Layered configuration: environment > config file > defaults."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else CONFIG_FILE
        self._data: Dict[str, Any] = {}
        self.reload()

    # -- io ---------------------------------------------------------------- #
    def reload(self) -> None:
        self._data = json.loads(json.dumps(DEFAULT_SETTINGS))
        raw = None
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            raw = None
        if isinstance(raw, dict):
            for key, value in raw.items():
                self._data[key] = value
            self._data.setdefault("secrets", {})

    def save(self) -> None:
        ensure_dirs()
        payload = dict(self._data)
        secrets = payload.pop("secrets", {}) or {}
        payload["secrets"] = secrets
        _atomic_write(self.path, json.dumps(payload, indent=2, sort_keys=True) + "\n", 0o600)

    # -- access ------------------------------------------------------------ #
    def get(self, key: str, default: Any = None) -> Any:
        if key in os.environ:
            return os.environ[key]
        return self._data.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        try:
            return float(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def update(self, values: Dict[str, Any]) -> None:
        self._data.update(values)

    def as_dict(self, redact: bool = True) -> Dict[str, Any]:
        out = json.loads(json.dumps(self._data))
        if redact:
            out.pop("secrets", None)
        return out

    # -- secrets ----------------------------------------------------------- #
    def api_key(self, provider: str) -> Optional[str]:
        """Environment first, then the local store. Never logs the value."""
        spec = PROVIDERS.get(provider)
        if spec:
            value = os.environ.get(spec.env_var)
            if value:
                return value.strip()
        secrets = self._data.get("secrets") or {}
        value = secrets.get(provider)
        return value.strip() if isinstance(value, str) and value.strip() else None

    def set_api_key(self, provider: str, key: str) -> None:
        secrets = self._data.setdefault("secrets", {})
        if key:
            secrets[provider] = key.strip()
        else:
            secrets.pop(provider, None)
        self.save()

    def clear_api_key(self, provider: str) -> None:
        secrets = self._data.setdefault("secrets", {})
        secrets.pop(provider, None)
        self.save()

    def configured_providers(self) -> List[str]:
        return [name for name in PROVIDERS if self.api_key(name)]

    def provider_report(self) -> List[Dict[str, Any]]:
        rows = []
        for name, spec in sorted(PROVIDERS.items()):
            env_present = bool(os.environ.get(spec.env_var))
            stored = bool((self._data.get("secrets") or {}).get(name))
            rows.append(
                {
                    "provider": name,
                    "env_var": spec.env_var,
                    "purpose": spec.purpose,
                    "signup": spec.signup,
                    "free_tier": spec.free_tier,
                    "configured": bool(env_present or stored),
                    "source": "environment" if env_present else ("config" if stored else None),
                }
            )
        return rows

    def mode_is_secure(self) -> bool:
        try:
            return not bool(self.path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))
        except OSError:
            return False


def load_config(path: Optional[Path] = None) -> Config:
    return Config(path=path)
