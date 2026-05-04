"""
SentinelView — Client organization profile (``client_profile.json``).

Separate from ``client_policy.json`` (SIEM / analysis onboarding). Stores org metadata,
data posture, compliance goals, environment, and a derived **risk profile**.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from client_workspace import clients_root

SCHEMA_VERSION = 1

INDUSTRY_VERTICALS: tuple[str, ...] = (
    "SaaS",
    "Healthcare",
    "Retail",
    "Financial Services",
    "Other",
)

# label → id (stored in JSON)
DATA_TYPE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("PII", "pii"),
    ("PHI", "phi"),
    ("PCI / Credit Card Data", "pci"),
    ("Intellectual Property", "ip"),
)

COMPLIANCE_GOAL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("SOC 2", "SOC2"),
    ("HIPAA", "HIPAA"),
    ("ISO 27001", "ISO27001"),
    ("GDPR", "GDPR"),
)

SYSTEM_ENVIRONMENT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Windows-first", "windows_first"),
    ("Cloud-native", "cloud_native"),
    ("Hybrid", "hybrid"),
)


def client_profile_path(client_id: str, cwd: Path | None = None) -> Path:
    return clients_root(cwd) / client_id / "client_profile.json"


def compute_risk_profile(
    industry_vertical: str,
    data_type_ids: list[str],
    compliance_goal_ids: list[str],
    system_environment: str,
) -> tuple[str, str]:
    """
    Derive initial risk profile (Low / Medium / High) and a short rationale.

    Rules (examples):
    - **High:** PHI or PCI selected; or regulated vertical (Healthcare / Financial Services)
      combined with PII; or HIPAA compliance goal with PHI-class exposure implied.
    - **Medium:** PII without High triggers; mixed posture (e.g. PII + Retail/SaaS).
    - **Low:** Intellectual Property only, or no sensitive data types selected.
    """
    dt = {x.strip().casefold() for x in data_type_ids}
    cg = {x.strip().casefold() for x in compliance_goal_ids}
    iv = (industry_vertical or "").strip()
    _ = system_environment  # stored on profile; reserved for future risk weighting

    reasons: list[str] = []

    # Highest sensitivity data categories
    if "phi" in dt:
        reasons.append("PHI is in scope (regulated health information).")
        return "High", " ".join(reasons)
    if "pci" in dt:
        reasons.append("PCI / payment card data is in scope.")
        return "High", " ".join(reasons)

    # Regulated industries + PII
    if "pii" in dt and iv in ("Healthcare", "Financial Services"):
        reasons.append(
            f"PII combined with a regulated vertical ({iv}) elevates inherent risk."
        )
        return "High", " ".join(reasons)

    # PII alone or with less sensitive verticals
    if "pii" in dt:
        if iv == "Retail":
            reasons.append("PII in retail context (customer data, transactions).")
            return "Medium", " ".join(reasons)
        reasons.append("Personally identifiable information is stored or processed.")
        return "Medium", " ".join(reasons)

    # Compliance aspirations without sensitive data types listed
    if "hipaa" in cg and not dt.intersection({"phi", "pii"}):
        reasons.append(
            "HIPAA listed as a goal; confirm data inventory aligns with minimum necessary."
        )
        return "Medium", " ".join(reasons)

    # IP / trade secrets — typically lower inherent privacy risk than PHI/PCI
    if "ip" in dt and dt <= {"ip"}:
        reasons.append("Primarily intellectual property; lower baseline privacy exposure.")
        return "Low", " ".join(reasons)

    if not dt:
        reasons.append("No sensitive data categories selected; confirm inventory for accuracy.")
        return "Low", " ".join(reasons)

    # Fallback (e.g. IP + something else not caught above)
    if "ip" in dt:
        return "Medium", "Mixed data types including intellectual property; validate scope."

    return "Medium", "Review selections against your data inventory and threat model."


def build_client_profile_document(
    organization_name: str,
    industry_vertical: str,
    data_type_ids: list[str],
    compliance_goal_ids: list[str],
    system_environment: str,
) -> dict[str, Any]:
    risk, rationale = compute_risk_profile(
        industry_vertical,
        data_type_ids,
        compliance_goal_ids,
        system_environment,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "organization_name": (organization_name or "").strip(),
        "industry_vertical": industry_vertical.strip(),
        "data_types_stored": list(data_type_ids),
        "compliance_goals": list(compliance_goal_ids),
        "system_environment": system_environment.strip(),
        "risk_profile": risk,
        "risk_rationale": rationale,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_client_profile_file(
    client_id: str,
    organization_name: str,
    industry_vertical: str,
    data_type_ids: list[str],
    compliance_goal_ids: list[str],
    system_environment: str,
    cwd: Path | None = None,
) -> Path:
    """Write ``clients/<client_id>/client_profile.json``."""
    root = clients_root(cwd) / client_id
    root.mkdir(parents=True, exist_ok=True)
    doc = build_client_profile_document(
        organization_name,
        industry_vertical,
        data_type_ids,
        compliance_goal_ids,
        system_environment,
    )
    path = root / "client_profile.json"
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def load_client_profile(client_id: str, cwd: Path | None = None) -> dict[str, Any] | None:
    p = client_profile_path(client_id, cwd)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def id_to_data_type_label(data_type_id: str) -> str:
    rev = {sid: lab for lab, sid in DATA_TYPE_OPTIONS}
    return rev.get(data_type_id.strip(), data_type_id)


def business_context_message(profile: dict[str, Any] | None) -> str:
    """
    Short narrative for the dashboard “Business context” card — ties onboarding selections
    to why SentinelView highlights certain findings.
    """
    if not profile:
        return (
            "Complete the **Client Onboarding Wizard** so SentinelView can explain monitoring "
            "focus (data classes, industry, and compliance goals) alongside your alerts."
        )
    vertical = str(profile.get("industry_vertical") or "your industry").strip()
    dt_ids = profile.get("data_types_stored")
    if not isinstance(dt_ids, list):
        dt_ids = []
    labels = [id_to_data_type_label(str(x)) for x in dt_ids if str(x).strip()]
    risk = str(profile.get("risk_profile") or "").strip()
    if not labels:
        return (
            f"Profile: **{vertical}** — inherent risk tier **{risk or '—'}**. "
            "Log flagging uses your **Onboarding** policy, **settings.yaml**, and detector "
            "rules; add data types in the wizard for tighter context."
        )
    focus = ", ".join(labels)
    return (
        f"Monitoring is framed for **{vertical}** with emphasis on **{focus}**. "
        f"Alerts surface exposure and access patterns that threaten that posture "
        f"(inherent risk **{risk or '—'}** per your saved profile)."
    )
