"""Dependency and configuration security checks (SCA-lite).

Audits the *local* environment rather than a remote target:

* Parses ``requirements.txt`` and reports pins that are missing, wildcarded or
  known-risky families.
* Verifies the interpreter version against the framework's own floor.
* Checks that the config/secret store is not world-readable and that no
  credential-looking file is sitting in the project tree.
* Optionally queries OSV (Open Source Vulnerabilities) for exact pinned versions —
  the only network call, and it is skipped when offline.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.config import PROVIDERS, REPO_ROOT, Config
from core.net import http_request
from core.utils import now_iso

NAME = "deps"
TITLE = "Dependency & Config Audit"
DESCRIPTION = "Audit pinned dependencies, interpreter version, secret-file permissions and local credential leakage"
CATEGORY = "security"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

OSV_API = "https://api.osv.dev/v1/query"

PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;#]+)?")
SECRET_NAMES = {
    ".env", ".env.local", "config.json", "secrets.json", "credentials.json",
    "id_rsa", "id_ed25519", ".ruk_secret",
}
SECRET_VALUE_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
)


def _parse_requirements(path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return entries
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = PIN_RE.match(line)
        if not match:
            continue
        name, operator, version = match.group(1), match.group(2), match.group(3)
        entries.append(
            {
                "name": name,
                "operator": operator,
                "version": version,
                "pinned_exactly": operator == "==" and bool(version),
                "raw": line,
            }
        )
    return entries


def _scan_tree(root: Path, limit: int = 400) -> List[str]:
    """Look for credential-looking files accidentally present in the tree."""
    found: List[str] = []
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "reports"}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            if name in SECRET_NAMES:
                found.append(str(Path(base, name).relative_to(root)))
            if len(found) >= limit:
                return found
    return found


def _gitignore_covers(root: Path) -> Tuple[bool, List[str]]:
    ignore_path = root / ".gitignore"
    if not ignore_path.exists():
        return False, []
    try:
        text = ignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, []
    required = [".env", "*.key", "config.json"]
    present = [item for item in required if item in text or item.replace(".", "") in text]
    return True, present


def _osv_query(name: str, version: str, timeout: float = 12.0) -> List[Dict[str, Any]]:
    payload = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).encode()
    import urllib.request

    request = urllib.request.Request(
        OSV_API, data=payload, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read(512 * 1024).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - offline must degrade, not crash
        return []
    vulns = data.get("vulns") or []
    out = []
    for vuln in vulns[:25]:
        out.append(
            {
                "id": vuln.get("id"),
                "summary": vuln.get("summary"),
                "severity": _osv_severity(vuln),
            }
        )
    return out


def _osv_severity(vuln: Dict[str, Any]) -> str:
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score") or "")
        if score.startswith("CVSS:"):
            parts = score.split("/")
            if len(parts) >= 2 and ":" in parts[-1]:
                return "high"
    text = (str(vuln.get("database_specific", {}).get("severity") or "")).upper()
    return {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}.get(text, "medium")


def audit(
    target: str = "",
    config: Optional[Config] = None,
    root: Optional[Path] = None,
    online: bool = True,
) -> Dict[str, Any]:
    config = config or Config()
    project = Path(root) if root else REPO_ROOT
    result: Dict[str, Any] = {
        "ok": True,
        "module": NAME,
        "target": target or str(project),
        "queried_at": now_iso(),
        "findings": [],
    }
    findings: List[Dict[str, Any]] = result["findings"]

    major, minor = sys.version_info[:2]
    result["python"] = {"version": sys.version.split()[0], "executable": sys.executable}
    if (major, minor) < (3, 8):
        findings.append(
            {
                "severity": "high",
                "title": f"Python {major}.{minor} is below the supported floor (3.8)",
                "detail": "Upgrade the interpreter; older versions lack security fixes.",
            }
        )

    requirements = project / "requirements.txt"
    deps = _parse_requirements(requirements)
    result["dependencies"] = deps
    unpinned = [dep["name"] for dep in deps if not dep["pinned_exactly"]]
    if unpinned:
        findings.append(
            {
                "severity": "low",
                "title": f"{len(unpinned)} dependency pin(s) not exact",
                "detail": "Not pinned to ==: " + ", ".join(unpinned[:10]),
                "reference": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
            }
        )

    if online and deps:
        checked = [dep for dep in deps if dep["pinned_exactly"]][:12]
        vulnerable: List[Dict[str, Any]] = []
        for dep in checked:
            for vuln in _osv_query(dep["name"], dep["version"]):
                vulnerable.append({**vuln, "package": dep["name"], "version": dep["version"]})
                findings.append(
                    {
                        "severity": vuln.get("severity", "medium"),
                        "title": f"{dep['name']} {dep['version']} — {vuln.get('id')}",
                        "detail": vuln.get("summary") or "Known vulnerability reported by OSV.",
                        "reference": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                    }
                )
        result["osv_checked"] = len(checked)
        result["osv_vulnerable"] = vulnerable

    leaked = _scan_tree(project)
    result["credential_files_in_tree"] = leaked
    for path in leaked:
        severity = "critical" if path.endswith((".env", ".env.local")) or "credential" in path else "high"
        findings.append(
            {
                "severity": severity,
                "title": f"Credential-looking file inside the project tree: {path}",
                "detail": "Remove it, add it to .gitignore and rotate any value it held.",
            }
        )

    has_ignore, covered = _gitignore_covers(project)
    result["gitignore"] = {"present": has_ignore, "covers": covered}
    if not has_ignore:
        findings.append(
            {
                "severity": "medium",
                "title": ".gitignore missing",
                "detail": "Without it, secrets and the local database can be committed by accident.",
            }
        )

    config_path = Path(config.path)
    secure = config.mode_is_secure()
    result["config_store"] = {
        "path": str(config_path),
        "exists": config_path.exists(),
        "mode_secure": secure,
    }
    if config_path.exists() and not secure:
        findings.append(
            {
                "severity": "medium",
                "title": "Config store is readable by other users",
                "detail": f"{config_path} is not mode 0600; stored API keys are exposed to other local accounts.",
            }
        )

    configured = [name for name, spec in PROVIDERS.items() if config.api_key(name)]
    result["providers_configured"] = configured
    result["providers_declared"] = sorted(PROVIDERS.keys())

    if leaked or any(f["severity"] in ("critical", "high") for f in findings):
        result["risk"] = "high"
    elif findings:
        result["risk"] = "medium" if any(f["severity"] == "medium" for f in findings) else "low"
    else:
        result["risk"] = "info"
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
    result["score"] = min(100, sum(weights.get(f["severity"], 0) for f in findings))
    result["summary"] = (
        f"{len(deps)} dependency line(s), {len(findings)} finding(s), "
        f"{len(configured)}/{len(PROVIDERS)} provider key(s) configured"
    )
    return result


def run(target: str = "", config: Optional[Config] = None, **options: Any) -> Dict[str, Any]:
    return audit(
        target,
        config=config,
        root=options.get("root"),
        online=bool(options.get("online", True)),
    )
