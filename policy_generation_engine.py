"""
SentinelView — Policy Generation Engine (client_profile.json–driven).

Composes **Data Handling**, **Access Control**, and **Incident Response** Markdown with
placeholders filled from the client profile. Optional skeleton comments live under
``policy_templates/`` for documentation; **runtime text is built in this module** so
conditionals (e.g. PII → personal data sanitization) stay explicit.

Each policy ends with a **Compliance Reference** table: **Trust Services Criteria** when
``compliance_goals`` includes **SOC2**, else **ISO/IEC 27001:2022 Annex A** (illustrative).

PDF output reuses ``policy_generator.build_policies_pdf_bytes`` (fpdf2).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from client_profile import COMPLIANCE_GOAL_OPTIONS, DATA_TYPE_OPTIONS

# Label lookup for stored IDs
_ID_TO_DATA_LABEL = {sid: lab for lab, sid in DATA_TYPE_OPTIONS}
_ID_TO_GOAL_LABEL = {sid: lab for lab, sid in COMPLIANCE_GOAL_OPTIONS}


def _org(profile: Mapping[str, Any] | None, fallback: str = "Organization") -> str:
    if not profile:
        return fallback
    o = str(profile.get("organization_name") or "").strip()
    return o if o else fallback


def _industry(profile: Mapping[str, Any] | None) -> str:
    if not profile:
        return "General"
    return str(profile.get("industry_vertical") or "General").strip() or "General"


def _data_type_ids(profile: Mapping[str, Any] | None) -> set[str]:
    if not profile:
        return set()
    raw = profile.get("data_types_stored")
    if not isinstance(raw, list):
        return set()
    return {str(x).strip().casefold() for x in raw if str(x).strip()}


def _data_types_display(profile: Mapping[str, Any] | None) -> str:
    ids = sorted(_data_type_ids(profile))
    if not ids:
        return "(none specified in client profile — confirm inventory)"
    parts = [_ID_TO_DATA_LABEL.get(i, i) for i in ids]
    return ", ".join(parts)


def _compliance_goals_display(profile: Mapping[str, Any] | None) -> str:
    if not profile:
        return "—"
    raw = profile.get("compliance_goals")
    if not isinstance(raw, list) or not raw:
        return "—"
    parts = [_ID_TO_GOAL_LABEL.get(str(x).strip(), str(x)) for x in raw]
    return ", ".join(parts)


def _has_soc2(profile: Mapping[str, Any] | None) -> bool:
    if not profile:
        return False
    raw = profile.get("compliance_goals")
    if not isinstance(raw, list):
        return False
    return any(str(x).strip().upper() == "SOC2" for x in raw)


def _system_env_label(profile: Mapping[str, Any] | None) -> str:
    if not profile:
        return "—"
    env = str(profile.get("system_environment") or "").strip().casefold()
    mapping = {
        "windows_first": "Windows-first (traditional desktop / server footprint)",
        "cloud_native": "Cloud-native (SaaS and cloud provider IAM primary)",
        "hybrid": "Hybrid (on-premises and cloud services)",
    }
    return mapping.get(env, env or "—")


def _risk_line(profile: Mapping[str, Any] | None) -> str:
    if not profile:
        return "—"
    rp = str(profile.get("risk_profile") or "").strip()
    rat = str(profile.get("risk_rationale") or "").strip()
    if not rp:
        return "—"
    if rat:
        return f"**{rp}** — {rat}"
    return f"**{rp}**"


def _section_pii_sanitization(org: str) -> str:
    return f"""
### Personal data sanitization

**{org}** treats personally identifiable information (PII) as requiring controlled handling
end-to-end. Teams must:

1. **Minimize live data** in non-production systems; use realistic synthetic or masked data in
   development and test environments unless an exception is approved and documented.
2. **Sanitize before sharing** — remove or redact identifiers from exports, tickets, support
   attachments, and reports unless sharing is necessary and permitted.
3. **Secure disposal** — erase or destroy media and backups containing PII when retention ends,
   using methods appropriate to the medium (crypto erase, physical destruction, vendor-certified
   wiping).
4. **Logging & exports** — avoid embedding PII in application logs, URLs, or monitoring payloads
   where alternatives exist.

"""


def _section_phi(org: str, industry: str) -> str:
    return f"""
### Protected health information (PHI)

Where PHI may be processed, **{org}** (profile: **{industry}**) aligns handling with applicable
health-data obligations: minimum necessary access, workforce training, business associate
considerations, and breach assessment workflows when PHI may be impermissibly used or disclosed.

"""


def _section_pci(org: str) -> str:
    return f"""
### Payment card and PCI-scoped data

**{org}** restricts cardholder data to approved systems and flows. Engineering and finance teams
must follow segmentation (no card data in general file shares), approved payment processors, and
documented exception handling if legacy flows remain during remediation.

"""


def _section_ip(org: str) -> str:
    return f"""
### Intellectual property and confidential business information

**{org}** classifies trade secrets and proprietary materials; access is limited to those with a
need to know. Transfers outside the organization require approval and appropriate agreements.

"""


def compliance_reference_table(
    *,
    policy_name: str,
    rows: list[tuple[str, str, str]],
    use_soc2: bool,
) -> str:
    """Markdown table: section → TSC or ISO control → notes."""
    if use_soc2:
        header = "| Policy section | Trust Services Criteria (illustrative) | Notes |"
        sep = "| --- | --- | --- |"
        intro = (
            "_Illustrative mapping to AICPA Trust Services Criteria for Security, "
            "Confidentiality, and Availability (as applicable). Not a substitute for a formal "
            "SOC 2 examination._"
        )
    else:
        header = "| Policy section | ISO/IEC 27001:2022 Annex A (illustrative) | Notes |"
        sep = "| --- | --- | --- |"
        intro = (
            "_Illustrative mapping for internal documentation. Map to your certifier’s control "
            "set as needed._"
        )

    lines = [
        "## Compliance Reference",
        "",
        intro,
        "",
        header,
        sep,
    ]
    for sec, crit, note in rows:
        lines.append(f"| {sec} | {crit} | {note} |")
    lines.extend(["", f"_Policy: {policy_name}_", ""])
    return "\n".join(lines)


def _data_handling_tsc_rows() -> list[tuple[str, str, str]]:
    return [
        ("Purpose & scope", "CC2.2, CC3.1", "Communicates obligations for sensitive data."),
        ("Plain English requirements (core)", "CC5.1, CC6.1", "Control activities for data handling."),
        ("Personal data sanitization", "CC6.1, CC6.7", "Logical access & data disposal."),
        ("PHI / PCI / IP sections (when in scope)", "CC6.1, CC6.6", "Classification & restriction."),
        ("Framework mapping", "CC4.1", "Evidence of monitoring / criteria linkage."),
    ]


def _data_handling_iso_rows() -> list[tuple[str, str, str]]:
    return [
        ("Purpose & scope", "A.5.12, A.5.13", "Classification and labeling."),
        ("Plain English requirements (core)", "A.5.34, A.8.12", "PII protection & DLP alignment."),
        ("Personal data sanitization", "A.8.10", "Information deletion / sanitization."),
        ("PHI / PCI / IP sections (when in scope)", "A.5.33, A.8.24", "Records & cryptography."),
    ]


def _access_tsc_rows() -> list[tuple[str, str, str]]:
    return [
        ("Purpose", "CC2.2", "Internal communication of access obligations."),
        ("Identity & least privilege", "CC6.1, CC6.2", "Logical access security."),
        ("Authentication & MFA", "CC6.1", "Credentials and MFA for sensitive systems."),
        ("Privileged access", "CC6.2, CC6.3", "Restricted administrative paths."),
        ("Environment-specific notes", "CC6.8", "Change / environment boundaries."),
    ]


def _access_iso_rows() -> list[tuple[str, str, str]]:
    return [
        ("Purpose", "A.5.15", "Access control policy."),
        ("Identity & least privilege", "A.5.16, A.5.18", "Identity & access rights."),
        ("Authentication & MFA", "A.5.17", "Authentication information."),
        ("Privileged access", "A.8.2", "Privileged access rights."),
    ]


def _ir_tsc_rows() -> list[tuple[str, str, str]]:
    return [
        ("Roles & severity", "CC2.2, CC7.2", "Communication & incident detection."),
        ("Detection & analysis", "CC7.1, CC7.2", "Monitoring and anomaly response."),
        ("Containment & eradication", "CC7.3, CC7.4", "Incident response activities."),
        ("Recovery & reporting", "CC7.5, CC8.1", "Recovery; change during incident."),
        ("Post-incident", "CC4.2", "Evaluation and improvement."),
    ]


def _ir_iso_rows() -> list[tuple[str, str, str]]:
    return [
        ("Roles & severity", "A.5.24, A.5.26", "Planning & incident mgmt procedures."),
        ("Detection & analysis", "A.8.16", "Monitoring activities."),
        ("Containment & eradication", "A.5.27", "Learning from incidents."),
        ("Recovery & reporting", "A.5.29, A.5.33", "Business continuity & legal holds."),
    ]


def generate_data_handling_policy_engine(profile: Mapping[str, Any] | None) -> str:
    org = _org(profile)
    industry = _industry(profile)
    dts = _data_type_ids(profile)
    display_types = _data_types_display(profile)
    goals = _compliance_goals_display(profile)
    risk = _risk_line(profile)
    use_soc2 = _has_soc2(profile)

    conditional = ""
    if "pii" in dts:
        conditional += _section_pii_sanitization(org)
    if "phi" in dts:
        conditional += _section_phi(org, industry)
    if "pci" in dts:
        conditional += _section_pci(org)
    if "ip" in dts:
        conditional += _section_ip(org)

    if not conditional.strip():
        conditional = (
            "### Data-specific annex\n\n"
            "_No extended annex selected._ Add **PII**, **PHI**, **PCI**, or **IP** under "
            "**Client Onboarding Wizard** → Data types to auto-include tailored subsections.\n"
        )

    body = f"""# Data Handling Policy

**Organization:** {org}  
**Industry (client profile):** {industry}  
**Data types in scope:** {display_types}  
**Compliance goals:** {goals}  
**Inherent risk (profile):** {risk}

---

## 1. Purpose

This policy defines how **{org}** handles, stores, and protects information assets consistent with
its stated data inventory (**{display_types}**) and operating context (**{industry}**).
Operational monitoring (e.g. SentinelView privacy and exposure findings) supports enforcement but
does not replace ownership by data stewards and system owners.

## 2. Plain English requirements

1. **Inventory & ownership** — Maintain a current view of systems and repositories where in-scope
   data types may appear (including cloud SaaS, shares, and backups).

2. **Least exposure** — Sensitive information must not reside in broadly shared or public-style
   locations unless explicitly approved and supplemented with compensating controls.

3. **Retention & disposal** — Apply approved retention schedules; securely delete or anonymize data
   when no longer required.

4. **Third parties** — Contracts and reviews for vendors that process this data reflect security
   and privacy expectations, including breach notification where applicable.

5. **Awareness** — Personnel receive training proportionate to role and to applicable regulatory
   expectations reflected in this profile ({goals}).

{conditional}

---

## 3. Roles & accountability

- **Executive sponsor** — Supports policy adherence and exception governance.
- **Data / system owners** — Classify systems and approve sharing exceptions.
- **All workforce** — Report suspected mishandling or exposure through the incident channel.

---

"""

    rows = _data_handling_tsc_rows() if use_soc2 else _data_handling_iso_rows()
    body += compliance_reference_table(
        policy_name="Data Handling Policy",
        rows=rows,
        use_soc2=use_soc2,
    )

    body += f"""## Document control

_Generated by SentinelView Policy Generation Engine from `client_profile.json`._

**Generated (UTC):** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}
"""
    return body


def generate_access_control_policy_engine(profile: Mapping[str, Any] | None) -> str:
    org = _org(profile)
    industry = _industry(profile)
    env = _system_env_label(profile)
    goals = _compliance_goals_display(profile)
    risk = _risk_line(profile)
    use_soc2 = _has_soc2(profile)

    cloud_note = ""
    if str(profile.get("system_environment") or "").strip().casefold() == "cloud_native":
        cloud_note = (
            "\n8. **Cloud IAM** — Prefer centralized identity (IdP), SSO where feasible, and "
            "cloud-provider IAM roles over long-lived keys for automation.\n"
        )

    body = f"""# Access Control Policy

**Organization:** {org}  
**Industry (client profile):** {industry}  
**System environment:** {env}  
**Compliance goals:** {goals}  
**Inherent risk (profile):** {risk}

---

## 1. Purpose

This policy defines how **{org}** grants, reviews, and revokes access to information systems and
data, aligned with its environment (**{env}**) and regulatory posture ({goals}).

## 2. Plain English requirements

1. **Unique identities** — Individual accounts for production and collaboration (no shared
   credentials except approved break-glass procedures).

2. **Least privilege** — Default-deny posture; elevated rights require approval and periodic
   review.

3. **Authentication** — Strong authentication (including MFA) for remote access, administrator
   consoles, and systems handling sensitive data types listed in the client profile.

4. **Privileged access** — Administrative roles are limited, monitored, and reconciled against
   authoritative HR or identity records where applicable.

5. **Joiner / mover / leaver** — Timely updates when employment or role changes occur.

6. **Logging** — Security-relevant events are retained to support investigation and audit.

7. **Environment fit** — Controls are applied consistently across **{env}** workloads.{cloud_note}

---

## 3. Periodic access review

Managers or data owners attest to appropriateness of access at least annually or upon major
system changes; exceptions are documented with owners and expiry dates.

---

"""

    rows = _access_tsc_rows() if use_soc2 else _access_iso_rows()
    body += compliance_reference_table(
        policy_name="Access Control Policy",
        rows=rows,
        use_soc2=use_soc2,
    )

    body += f"""## Document control

_Generated by SentinelView Policy Generation Engine from `client_profile.json`._

**Generated (UTC):** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}
"""
    return body


def generate_incident_response_plan_engine(profile: Mapping[str, Any] | None) -> str:
    org = _org(profile)
    industry = _industry(profile)
    display_types = _data_types_display(profile)
    goals = _compliance_goals_display(profile)
    risk = _risk_line(profile)
    use_soc2 = _has_soc2(profile)

    breach_section = ""
    if _data_type_ids(profile).intersection({"pii", "phi", "pci"}):
        breach_section = f"""
## 3a. Breach assessment & notifications

Where in-scope data includes **{display_types}**, legal/privacy triage must assess whether
incidents trigger regulatory or contractual notification obligations, and document the decision
and timeline.

"""

    body = f"""# Incident Response Plan

**Organization:** {org}  
**Industry (client profile):** {industry}  
**Data types in scope:** {display_types}  
**Compliance goals:** {goals}  
**Inherent risk (profile):** {risk}

---

## 1. Objectives

Establish a consistent approach for detecting, responding to, and recovering from security
incidents affecting **{org}**, with clarity on severity, roles, and communications.

## 2. Severity & escalation

| Level | Description | Example triggers |
| --- | --- | --- |
| **Sev1** | Organization-wide or severe data exposure | Suspected bulk exfiltration, ransomware |
| **Sev2** | Material but contained | Privileged misuse, targeted phishing success |
| **Sev3** | Limited impact | Single account compromise without lateral movement |

Escalate Sev1 immediately to executive leadership and legal.

## 3. Response phases

1. **Detect & triage** — Validate alerts (including SentinelView detections), preserve evidence,
   assign an incident commander.
2. **Contain** — Isolate hosts, revoke credentials, block malicious infrastructure as appropriate.
3. **Eradicate & recover** — Remove persistence, patch root cause, restore from trusted backups.
4. **Post-incident** — Lessons learned, control updates, and tracking of corrective actions.

{breach_section}---

## 4. Roles (customize names locally)

| Role | Responsibility |
| --- | --- |
| Incident Commander | Owns timeline, comms, and decisions |
| Technical Lead | Forensics, containment, recovery |
| Legal / Privacy | Regulatory reporting, external counsel |
| Comms / PR | Customer and public messaging if needed |

---

"""

    rows = _ir_tsc_rows() if use_soc2 else _ir_iso_rows()
    body += compliance_reference_table(
        policy_name="Incident Response Plan",
        rows=rows,
        use_soc2=use_soc2,
    )

    body += f"""## Document control

_Generated by SentinelView Policy Generation Engine from `client_profile.json`._

**Generated (UTC):** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}
"""
    return body


def generate_policies_from_client_profile(
    profile: Mapping[str, Any] | None,
) -> dict[str, str]:
    """
    Build all three Markdown policies from ``client_profile.json`` content.

    Returns title → body. If ``profile`` is None, returns empty dict.
    """
    if not profile:
        return {}
    return {
        "Data Handling Policy": generate_data_handling_policy_engine(profile),
        "Access Control Policy": generate_access_control_policy_engine(profile),
        "Incident Response Plan": generate_incident_response_plan_engine(profile),
    }


def policies_engine_markdown_bundle(
    policies: dict[str, str],
    organization: str,
) -> str:
    """Single Markdown file combining engine-generated policies."""
    org = (organization or "Organization").strip() or "Organization"
    lines = [
        f"# Policy Package — {org}",
        "",
        "_Generated by SentinelView Policy Generation Engine (client profile–driven)._",
        f"_Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}_",
        "",
        "---",
        "",
    ]
    for title, body in policies.items():
        lines.append(body.strip())
        lines.extend(["", "---", ""])
    return "\n".join(lines).rstrip() + "\n"
