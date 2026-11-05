"""Phone number intelligence — offline structural analysis.

What this really does (and what it deliberately does not):

* Parses E.164 / international / national formats and normalises them.
* Resolves the country, ISO code and dialling code **offline** from a bundled
  table, so it works on a plane and on a bare Termux install.
* Reports the national-number length plausibility against that country's
  published length range.
* Infers line type (mobile / landline / VoIP) **only where the published
  numbering plan gives unambiguous prefix rules** — otherwise it returns
  ``"unknown"`` rather than guessing.
* Optionally enriches carrier + line type through the numverify API when the
  operator supplies a key.

It does NOT locate the handset, read messages, or reveal the subscriber. Those
require lawful access that this framework does not have and will not simulate.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from core.config import PROVIDERS, Config
from core.providers import api_get, degraded, require_key
from core.errors import NetworkError, ProviderNotConfigured
from core.utils import now_iso

from data import phone_codes

NAME = "phone"
TITLE = "Phone Intelligence"
DESCRIPTION = "Validate an international number, resolve country/calling code, infer line type"
CATEGORY = "mobile"
ACTIVE = False
REQUIRES: Tuple[str, ...] = ()

_SEPARATORS = re.compile(r"[\s\-().\u00a0\u2011\u2013]+")
_EXTENSION = re.compile(r"(?:ext|x|#)\.?\s*(\d{1,6})$", re.IGNORECASE)


def normalise(raw: str) -> Dict[str, str]:
    """Strip formatting, keep a leading ``+`` and any extension."""
    text = str(raw or "").strip()
    extension = ""
    match = _EXTENSION.search(text)
    if match:
        extension = match.group(1)
        text = text[: match.start()].strip()
    text = _SEPARATORS.sub("", text)
    text = text.replace("tel:", "").replace("phone:", "")
    plus = text.startswith("+")
    digits = "".join(ch for ch in text if ch.isdigit())
    if text.startswith("00"):
        plus = True
        digits = digits[2:]
    return {"digits": digits, "plus": "yes" if plus else "no", "extension": extension}


def _infer_line_type(code: str, national: str) -> Tuple[str, str]:
    """Return ``(line_type, basis)``.

    Only rules that are genuinely published and unambiguous are applied. Anything
    else is ``unknown`` with the reason spelled out — a confident wrong answer is
    worse than an honest gap for this kind of tool.
    """
    if not national:
        return "unknown", "no national digits"

    # North American Numbering Plan: NPA-NXX, where the first digit of the
    # exchange (NXX) is 2-9. Fixed/mobile split is per-LATA and not reliable.
    if code == "1" and len(national) == 10:
        if national[0] in "01":
            return "invalid", "NANP area code cannot start with 0 or 1"
        if national[3] in "01":
            return "invalid", "NANP exchange cannot start with 0 or 1"
        area = national[:3]
        if area in phone_codes.NANP:
            return "unknown", "NANP (caribbean) numbers do not encode line type"
        if area[1:3] in ("00", "11") or area in ("555",):
            return "invalid", f"NANP area code {area} is reserved"
        return "unknown", "NANP does not encode line type in the number"

    # United Kingdom: 07xxx mobile, 01/02/03 geographic or non-geographic.
    if code == "44":
        if national.startswith("7"):
            return "mobile", "UK 07x range is allocated to mobile services"
        if national.startswith(("1", "2", "3")):
            return "landline", "UK 01/02/03 ranges are geographic or non-geographic fixed"
        if national.startswith("9"):
            return "premium", "UK 09x is premium rate"
        if national.startswith("800"):
            return "tollfree", "UK 0800 is freephone"

    # Germany: 015x/016x/017x mobile, 030/040 etc geographic.
    if code == "49":
        if national.startswith(("15", "16", "17")):
            return "mobile", "DE 015/016/017 are mobile allocations"
        if national.startswith("800"):
            return "tollfree", "DE 0800 is freephone"
        if national.startswith("900"):
            return "premium", "DE 0900 is premium rate"
        return "landline", "DE remaining ranges are fixed-line"

    # India: 6-9 mobile, others fixed (TRAI published).
    if code == "91" and len(national) == 10:
        if national[0] in "6789":
            return "mobile", "IN numbers starting 6-9 are mobile allocations"
        return "landline", "IN numbers starting 2-5 are fixed-line"

    # Pakistan: 3xx mobile.
    if code == "92":
        if national.startswith("3"):
            return "mobile", "PK 3xx is the mobile range"
        return "landline", "PK remaining ranges are fixed"

    # Saudi Arabia: 5x mobile.
    if code == "966":
        if national.startswith("5"):
            return "mobile", "SA 5x is the mobile range"
        return "landline", "SA remaining ranges are fixed"

    # UAE: 5x mobile.
    if code == "971":
        if national.startswith("5"):
            return "mobile", "AE 5x is the mobile range"
        return "landline", "AE remaining ranges are fixed"

    # Australia: 4xx mobile.
    if code == "61":
        if national.startswith("4"):
            return "mobile", "AU 4xx is the mobile range"
        if national.startswith(("180", "1300")):
            return "tollfree", "AU 1800/1300 are freephone"
        return "landline", "AU remaining ranges are fixed"

    # Brazil: 9xxxxxxxx mobile (11 digits, after the 2-digit area code).
    if code == "55" and len(national) == 11:
        if national[2] == "9":
            return "mobile", "BR 9-digit mobile prefix"
        return "landline", "BR remaining ranges are fixed"

    # Italy: 3xx mobile.
    if code == "39":
        if national.startswith("3"):
            return "mobile", "IT 3xx is the mobile range"
        return "landline", "IT remaining ranges are fixed"

    # Russia/Kazakhstan: 9xx mobile.
    if code == "7":
        if national.startswith("9"):
            return "mobile", "RU/KZ 9xx is the mobile range"
        return "landline", "RU/KZ remaining ranges are fixed"

    # Nigeria: 70/80/81/90/91 mobile.
    if code == "234":
        if national.startswith(("70", "80", "81", "90", "91")):
            return "mobile", "NG 070/080/081/090/091 are mobile"
        return "landline", "NG remaining ranges are fixed"

    # Kenya: 7xx/1xx mobile.
    if code == "254":
        if national.startswith(("7", "1")):
            return "mobile", "KE 7xx/1xx are mobile"
        return "landline", "KE remaining ranges are fixed"

    return "unknown", "no published prefix rule bundled for this country"


def _voip_markers(digits: str) -> List[str]:
    """Heuristic notes only — never presented as a determination."""
    notes: List[str] = []
    if re.search(r"(\d)\1{5,}", digits):
        notes.append("contains a run of 6+ identical digits (common in test/spoofed numbers)")
    if digits[-4:] in ("0000", "1111", "1234"):
        notes.append("ends in a patterned block (common in disposable numbers)")
    return notes


def analyse(raw: str) -> Dict[str, Any]:
    """Offline analysis of one number. Returns the module envelope."""
    result: Dict[str, Any] = {
        "ok": True,
        "module": NAME,
        "target": raw,
        "queried_at": now_iso(),
        "input": raw,
        "findings": [],
    }
    parts = normalise(raw)
    digits = parts["digits"]
    result["normalised"] = {
        "e164": f"+{digits}" if digits else "",
        "digits": digits,
        "had_plus_prefix": parts["plus"] == "yes",
        "extension": parts["extension"] or None,
    }

    if not digits:
        result["ok"] = False
        result["error"] = "no_digits"
        result["message"] = "No digits found in the input."
        return result

    if len(digits) < 7:
        result["ok"] = False
        result["error"] = "too_short"
        result["message"] = "Fewer than 7 digits: not a dialable number."
        return result
    if len(digits) > 17:
        result["ok"] = False
        result["error"] = "too_long"
        result["message"] = "More than 17 digits exceeds the E.164 maximum."
        return result

    code, national = phone_codes.split_international(digits)
    if code is None and parts["plus"] != "yes":
        # No plus prefix and no match: assume the operator supplied a national
        # number with a trunk zero we cannot interpret.
        result["ok"] = False
        result["error"] = "unknown_calling_code"
        result["message"] = (
            "No assigned country calling code matched. Supply the number in "
            "international format, e.g. +966501234567."
        )
        return result
    if code is None:
        result["ok"] = False
        result["error"] = "unknown_calling_code"
        result["message"] = "The leading digits do not match any assigned calling code."
        return result

    country = phone_codes.lookup_calling_code(code) or ("??", "Unknown", f"+{code}")
    iso, country_name, dial = country
    if code == "1":
        nanp = phone_codes.resolve_nanp(national)
        if nanp:
            iso, country_name = nanp

    hint = phone_codes.length_hint(code)
    plausible = True
    if hint:
        low, high = hint
        plausible = low <= len(national) <= high

    line_type, basis = _infer_line_type(code, national)
    e164 = f"+{code}{national}"

    result.update(
        {
            "country": {"iso": iso, "name": country_name, "calling_code": dial},
            "national_number": national,
            "e164": e164,
            "formats": {
                "e164": e164,
                "international": f"{dial} {national}",
                "national": f"0{national}" if line_type in ("landline", "mobile") else national,
                "uri": f"tel:+{code}{national}",
            },
            "length": {
                "national_digits": len(national),
                "expected_range": list(hint) if hint else None,
                "plausible": plausible,
            },
            "line_type": line_type,
            "line_type_basis": basis,
            "validity": {
                "format_valid": plausible,
                "confidence": "format_only",
                "note": (
                    "Format and length were checked against the published numbering "
                    "plan. Number existence and reachability cannot be verified "
                    "offline and are not claimed here."
                ),
            },
            "notes": _voip_markers(digits),
            "summary": f"{e164} — {country_name} ({iso}), {line_type}",
        }
    )

    if not plausible:
        result["findings"].append(
            {
                "severity": "low",
                "title": f"National number length {len(national)} outside published range {hint}",
                "detail": f"{iso} expects {hint[0]}-{hint[1]} digits after {dial}.",
                "reference": "ITU-T E.164 numbering plan",
            }
        )
    if line_type == "premium":
        result["findings"].append(
            {
                "severity": "info",
                "title": "Premium rate range",
                "detail": "Calls to this range are charged above standard rates.",
            }
        )
    if line_type == "invalid":
        result["findings"].append(
            {
                "severity": "medium",
                "title": "Number is structurally invalid",
                "detail": basis,
                "reference": "National numbering plan",
            }
        )
    return result


def enrich_with_numverify(e164: str, config: Optional[Config] = None) -> Dict[str, Any]:
    """Optional carrier enrichment. Degrades cleanly without a key."""
    config = config or Config()
    try:
        key = require_key(config, "numverify")
    except ProviderNotConfigured as exc:
        spec = PROVIDERS["numverify"]
        return degraded("numverify", spec.env_var, spec.purpose)

    url = "http://apilayer.net/api/validate"
    try:
        response = api_get(
            f"{url}?access_key={key}&number={e164.replace('+', '')}&format=1", timeout=12.0
        )
    except NetworkError as exc:
        return {"ok": False, "degraded": True, "provider": "numverify", "error": "network_error",
                "message": str(exc)}

    if not response["ok"]:
        return {
            "ok": False,
            "degraded": True,
            "provider": "numverify",
            "error": response.get("error") or "provider_error",
            "status": response.get("status"),
            "message": "numverify rejected the request; check the key and plan quota.",
        }
    data = response.get("data") or {}
    if isinstance(data, dict) and data.get("success") is False:
        error = data.get("error") or {}
        return {
            "ok": False,
            "degraded": True,
            "provider": "numverify",
            "error": str(error.get("type") or "provider_error"),
            "message": str(error.get("info") or "numverify returned an error"),
        }
    return {
        "ok": True,
        "provider": "numverify",
        "valid": bool(data.get("valid")),
        "number": data.get("number"),
        "local_format": data.get("local_format"),
        "international_format": data.get("international_format"),
        "country_prefix": data.get("country_prefix"),
        "country_code": data.get("country_code"),
        "country_name": data.get("country_name"),
        "location": data.get("location"),
        "carrier": data.get("carrier"),
        "line_type": data.get("line_type"),
    }


def run(target: str, enrich: bool = False, config: Optional[Config] = None, **_: Any) -> Dict[str, Any]:
    """Module entry point."""
    result = analyse(target)
    if result.get("ok") and enrich:
        result["enrichment"] = enrich_with_numverify(result["e164"], config)
    elif enrich:
        result["enrichment"] = {
            "ok": False,
            "error": "skipped",
            "message": "Enrichment needs a valid number first.",
        }
    if result.get("ok"):
        types = result.get("line_type")
        risk = "info"
        if types == "invalid":
            risk = "medium"
        result["risk"] = risk
        result["score"] = {"info": 0, "medium": 40}.get(risk, 0)
    return result
