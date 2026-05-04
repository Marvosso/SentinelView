"""
SentinelView — Response tracking: remediation step choices for closed-loop audit trail.
"""

from __future__ import annotations


def remediation_step_choices(source_log: str, risk_level: str) -> list[str]:
    """
    Dropdown options for which remediation step the operator performed.
    Aligned with Critical access and High privacy playbooks; always includes generic exits.
    """
    sl = source_log.strip().casefold()
    rl = risk_level.strip().casefold()
    specific: list[str] = []

    if sl == "access_review" and rl == "critical":
        specific = [
            "Revoked credentials / disabled account for the affected ID",
            "Completed audit of recent login activity and active sessions",
            "Updated HR roster or provisioning so access matches policy",
            "Filed / updated ITSM or GRC ticket with owner and due date",
        ]
    elif sl == "privacy_scan" and rl == "critical":
        specific = [
            "Declared incident per playbook — isolated asset from broad network access",
            "Moved content to Secure Vault and revoked public/share ACLs immediately",
            "Opened formal IR / privacy escalation with timestamped chain of custody",
            "Initiated regulatory / breach-notification evaluation per counsel",
            "Notified executive sponsor and customer communications owner if applicable",
        ]
    elif sl == "privacy_scan" and rl == "high":
        specific = [
            "Moved the identified file to the Secure Vault (or equivalent)",
            "Updated folder or share permissions to remove public exposure",
            "Removed or redacted PII from the reported location",
            "Notified data owner, privacy office, or security leadership",
        ]
    else:
        specific = [
            "Completed prescribed steps from internal incident-response playbook",
        ]

    tail = [
        "Partial completion — follow-up ticket opened",
        "Other (document details in resolution notes)",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for x in specific + tail:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def widget_key_safe(event_id: str, suffix: str) -> str:
    """Streamlit widget keys must be stable and alphanumeric-ish."""
    safe = "".join(c if c.isalnum() else "_" for c in str(event_id))[:80]
    return f"{suffix}_{safe}"
