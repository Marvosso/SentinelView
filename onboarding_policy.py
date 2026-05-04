"""
SentinelView — Client onboarding: derive ``client_policy.json`` from business profile.

Selections drive ``alert_sensitivity.pii_in_public_path`` (Medium / High / Critical) and
optional ``derived_pii_keywords`` merged into analysis at load time (see ``settings_loader``).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from client_workspace import clients_root

BUSINESS_TYPES: tuple[str, ...] = (
    "Healthcare",
    "FinTech",
    "E-commerce",
    "SaaS / B2B",
    "General / Other",
)

# label → stable id
DATA_SENSITIVITY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("We store SSNs or national IDs", "ssn"),
    ("We store payment card / PCI-scoped data", "pci"),
    ("We store health records / PHI-class data", "phi"),
    ("We only store emails or basic contact info", "contact_only"),
)

REGULATORY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("SOC 2", "SOC2"),
    ("HIPAA", "HIPAA"),
    ("GDPR", "GDPR"),
    ("PCI DSS", "PCI_DSS"),
)

# Where people work — drives Access Control policy generation
WORKFORCE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Primarily on-site / office-based", "onsite"),
    ("Hybrid or remote employees", "remote"),
)


def resolve_client_policy_path(data_dir: Path | None) -> Path | None:
    """
    If ``data_dir`` is ``.../clients/<id>/data``, return ``.../clients/<id>/client_policy.json``
    when that file exists.
    """
    if data_dir is None:
        return None
    d = data_dir.resolve()
    try:
        if d.name != "data":
            return None
        if d.parent.parent.name != "clients":
            return None
    except IndexError:
        return None
    p = d.parent / "client_policy.json"
    return p if p.is_file() else None


def client_policy_path_for_client(client_id: str, cwd: Path | None = None) -> Path:
    """Absolute path to ``clients/<client_id>/client_policy.json``."""
    return clients_root(cwd) / client_id / "client_policy.json"


def _tier_to_public_risk(tier: int) -> str:
    if tier >= 3:
        return "Critical"
    if tier >= 2:
        return "High"
    return "Medium"


def compute_alert_profile(
    business_type: str,
    data_sensitivity_ids: list[str],
    regulatory_ids: list[str],
) -> tuple[dict[str, Any], list[str]]:
    """
    Derive ``alert_sensitivity`` block and keyword hints from onboarding selections.

    Returns ``(alert_sensitivity_dict, derived_pii_keywords)``.
    """
    bt = (business_type or "General / Other").strip()
    sens = {x.strip().casefold() for x in data_sensitivity_ids}
    reg = {x.strip().casefold() for x in regulatory_ids}

    # Baseline tier by vertical (PII-in-public path severity floor)
    tier = 2  # High
    if bt == "FinTech":
        tier = 3
    elif bt == "Healthcare":
        tier = 3
    elif bt == "E-commerce":
        tier = 2
    elif bt == "SaaS / B2B":
        tier = 2
    else:
        tier = 2

    keywords: list[str] = []

    if "ssn" in sens:
        tier = max(tier, 3)
        keywords.extend(["SSN", "Social Security", "national ID"])
    if "pci" in sens:
        tier = max(tier, 3)
        keywords.extend(["PAN", "credit card", "PCI", "payment card"])
    if "phi" in sens:
        tier = max(tier, 3)
        keywords.extend(["PHI", "HIPAA", "patient", "clinical"])
    if sens == {"contact_only"} and bt not in ("FinTech", "Healthcare"):
        tier = min(tier, 1)

    if "hipaa" in reg:
        tier = max(tier, 3)
        keywords.extend(["HIPAA"])
    if "pci_dss" in reg:
        tier = max(tier, 3)
    if "gdpr" in reg:
        tier = max(tier, 2)
        keywords.extend(["GDPR", "personal data"])
    if "soc2" in reg:
        tier = max(tier, 2)

    if bt == "FinTech":
        tier = 3

    pii_public = _tier_to_public_risk(tier)

    alert = {
        "pii_in_public_path": pii_public,
        "pii_in_public_rationale": _rationale(bt, sens, reg, pii_public),
        "access_review_baseline": "Critical_when_admin_off_roster",
    }

    # Dedupe keyword list, preserve order
    seen: set[str] = set()
    out_kw: list[str] = []
    for k in keywords:
        k2 = k.strip()
        if k2 and k2 not in seen:
            seen.add(k2)
            out_kw.append(k2)

    return alert, out_kw


def _rationale(
    business: str, sens: set[str], reg: set[str], level: str
) -> str:
    parts = [f"vertical={business!r}", f"level={level}"]
    if sens:
        parts.append("sensitivity=" + "+".join(sorted(sens)))
    if reg:
        parts.append("reg=" + "+".join(sorted(reg)))
    return "; ".join(parts)


def build_client_policy_document(
    business_type: str,
    data_sensitivity_ids: list[str],
    regulatory_ids: list[str],
    *,
    workforce_model: str = "onsite",
) -> dict[str, Any]:
    alert, derived_kw = compute_alert_profile(
        business_type, data_sensitivity_ids, regulatory_ids
    )
    wf = (workforce_model or "onsite").strip()
    if wf not in ("onsite", "remote"):
        wf = "onsite"
    return {
        "schema_version": 2,
        "business_type": business_type,
        "data_sensitivity": list(data_sensitivity_ids),
        "regulatory_targets": list(regulatory_ids),
        "workforce_model": wf,
        "alert_sensitivity": alert,
        "derived_pii_keywords": derived_kw,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_client_policy_file(
    client_id: str,
    business_type: str,
    data_sensitivity_ids: list[str],
    regulatory_ids: list[str],
    cwd: Path | None = None,
    *,
    workforce_model: str = "onsite",
) -> Path:
    """Write ``clients/<client_id>/client_policy.json`` and return the path."""
    root = clients_root(cwd) / client_id
    root.mkdir(parents=True, exist_ok=True)
    doc = build_client_policy_document(
        business_type,
        data_sensitivity_ids,
        regulatory_ids,
        workforce_model=workforce_model,
    )
    path = root / "client_policy.json"
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def load_client_policy(client_id: str, cwd: Path | None = None) -> dict[str, Any] | None:
    p = client_policy_path_for_client(client_id, cwd)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
