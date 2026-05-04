"""
SentinelView — Remediation Engine: maps risk categories to plain-English response steps.
"""

from __future__ import annotations

from typing import Final

# Risk type → operator-facing remediation (plain English).
REMEDIATION_BY_RISK_TYPE: Final[dict[str, str]] = {
    "Critical Access Risk": (
        "Immediate Action Required: Revoke credentials for this ID and audit "
        "recent login activity."
    ),
    "High Privacy Risk": (
        "Data Leak Detected: Move the identified file to the Secure Vault and "
        "update folder permissions."
    ),
    "Critical Privacy Risk": (
        "Regulatory-grade exposure: Treat as emergency data leak — isolate the asset, "
        "invoke incident response, notify privacy/security leadership per policy, "
        "and eliminate public-path exposure immediately."
    ),
}

_DEFAULT_REMEDIATION = (
    "Review this finding with your security team and follow internal "
    "incident-response playbooks."
)


def risk_type_key(risk_level_value: str, source_log: str) -> str | None:
    """Map technical severity + log source to a dictionary risk type label."""
    level = risk_level_value.strip().casefold()
    src = source_log.strip().casefold()
    if level == "critical" and src == "access_review":
        return "Critical Access Risk"
    if level == "critical" and src == "privacy_scan":
        return "Critical Privacy Risk"
    if level == "high" and src == "privacy_scan":
        return "High Privacy Risk"
    return None


def remediation_for(risk_level_value: str, source_log: str) -> str:
    """Return remediation text for the given risk level and log source."""
    key = risk_type_key(risk_level_value, source_log)
    if key is None:
        return _DEFAULT_REMEDIATION
    return REMEDIATION_BY_RISK_TYPE.get(key, _DEFAULT_REMEDIATION)
