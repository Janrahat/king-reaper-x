"""Module registry and result normalisation.

Every capability module exposes the same tiny contract:

    NAME                 unique string id, used by the CLI and the DB
    TITLE                human label
    DESCRIPTION          one line for `tools` and the dashboard
    CATEGORY             grouping key
    ACTIVE               bool — needs the per-run authorization gate
    REQUIRES             tuple of provider names (empty when offline capable)
    run(target, **opts)  -> dict

:func:`normalize` fills in the envelope fields so no module can forget them.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Dict, List, Optional

from .errors import ReaperError
from .utils import now_iso

#: module path -> (NAME it must expose)
MODULE_PACKAGES = [
    "modules.mobile_intelligence",
    "modules.whatsapp_intelligence",
    "modules.location_intelligence",
    "modules.osint",
    "modules.reconnaissance",
    "modules.network_security",
    "modules.web_security",
    "modules.threat_intelligence",
]


def normalize(result: Dict[str, Any], module: str, target: str, started: str) -> Dict[str, Any]:
    """Guarantee the envelope every consumer relies on."""
    if not isinstance(result, dict):
        result = {"ok": False, "error": "bad_module_return", "message": str(result)[:200]}
    result.setdefault("ok", True)
    result.setdefault("module", module)
    result.setdefault("target", target)
    result.setdefault("started", started)
    result.setdefault("finished", now_iso())
    findings = result.get("findings")
    if findings is None:
        result["findings"] = []
    elif not isinstance(findings, list):
        result["findings"] = list(findings)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if result["findings"]:
        worst = max(
            (severity_order.get(str(item.get("severity", "info")).lower(), 0) for item in result["findings"]),
            default=0,
        )
        result.setdefault("risk", {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst])
    result.setdefault("risk", result.get("risk", "info"))
    return result


def discover() -> List[Dict[str, Any]]:
    """Import every module package and collect its metadata."""
    found: List[Dict[str, Any]] = []
    for package_name in MODULE_PACKAGES:
        try:
            package = importlib.import_module(package_name)
        except Exception as exc:  # noqa: BLE001 - a broken module must not hide the rest
            found.append(
                {
                    "name": package_name.rsplit(".", 1)[-1],
                    "title": package_name,
                    "description": f"failed to import: {type(exc).__name__}: {exc}",
                    "category": "broken",
                    "active": False,
                    "requires": (),
                    "importable": False,
                }
            )
            continue
        for _finder, sub_name, is_pkg in pkgutil.iter_modules(package.__path__):
            # Module files (``reconnaissance/domain_intel.py``) and sub-packages
            # are both valid containers; skip only private helpers.
            if sub_name.startswith("_"):
                continue
            full = f"{package_name}.{sub_name}"
            try:
                sub = importlib.import_module(full)
            except Exception as exc:  # noqa: BLE001
                found.append(
                    {
                        "name": sub_name,
                        "title": full,
                        "description": f"failed to import: {type(exc).__name__}: {exc}",
                        "category": "broken",
                        "active": False,
                        "requires": (),
                        "importable": False,
                    }
                )
                continue
            if not hasattr(sub, "run") or not hasattr(sub, "NAME"):
                continue
            found.append(
                {
                    "name": sub.NAME,
                    "title": getattr(sub, "TITLE", sub.NAME),
                    "description": getattr(sub, "DESCRIPTION", ""),
                    "category": getattr(sub, "CATEGORY", "general"),
                    "active": bool(getattr(sub, "ACTIVE", False)),
                    "requires": tuple(getattr(sub, "REQUIRES", ()) or ()),
                    "importable": True,
                    "module": full,
                }
            )
    return found


def load(name: str) -> Optional[Any]:
    """Import and return the module object for *name*."""
    for meta in discover():
        if meta["name"] == name and meta.get("importable"):
            return importlib.import_module(meta["module"])
    return None


def category_map(entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for meta in entries if entries is not None else discover():
        grouped.setdefault(meta.get("category", "general"), []).append(meta)
    return grouped


def call(module_name: str, target: str, **options: Any) -> Dict[str, Any]:
    """Run a module by name and normalise/contain any exception."""
    started = now_iso()
    module = load(module_name)
    if module is None:
        return {
            "ok": False,
            "error": "unknown_module",
            "message": f"No module named '{module_name}'. Run `python main.py tools`.",
            "module": module_name,
            "target": target,
        }
    try:
        result = module.run(target, **options)
    except ReaperError as exc:
        return normalize(exc.as_dict(), module_name, target, started)
    except TypeError as exc:
        return normalize(
            {"ok": False, "error": "bad_arguments", "message": str(exc)}, module_name, target, started
        )
    except Exception as exc:  # noqa: BLE001 - the CLI must never see a raw traceback
        return normalize(
            {
                "ok": False,
                "error": "module_exception",
                "message": f"{type(exc).__name__}: {exc}",
            },
            module_name,
            target,
            started,
        )
    return normalize(result, module_name, target, started)
