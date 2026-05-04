"""
SentinelView — Export module: Compliance Summary Report for auditors and regulators.
Produces Markdown and PDF registers listing each event, detection date, mapped policy
interpretation, and remediation / resolution evidence.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

# Primary policy framing by detection channel and severity (evidence-oriented wording).
POLICY_BY_SOURCE_AND_RISK: dict[tuple[str, str], str] = {
    (
        "access_review",
        "Critical",
    ): (
        "NIST SP 800-53 Rev. 5 — AC-2 (Account Management), AC-6 (Least Privilege), "
        "and IA family controls for privileged access; "
        "CDD/KYC program alignment — customer and workforce identity assurance for "
        "high-risk / privileged roles (beneficial ownership and role verification)."
    ),
    (
        "privacy_scan",
        "High",
    ): (
        "NIST AI RMF 1.0 — Govern 1 (Policies, processes, and procedures for "
        "responsible AI and data use), Map 1 (Context is recognized and risks related "
        "to data and AI systems are identified); "
        "NIST Privacy Framework — Data Processing (inventory, mapping, and minimization); "
        "CDD/KYC-relevant confidentiality — safeguarding of customer-related and "
        "sensitive data where PII exposure elevates financial-crime or privacy risk."
    ),
    (
        "privacy_scan",
        "Critical",
    ): (
        "Elevated program posture (per client policy): NIST SP 800-53 — SI (System "
        "and Information Integrity), SC (System and Communications Protection), "
        "and AU (Audit and Accountability) where sensitive data may be exposed; "
        "NIST Privacy Framework — Control processing scope with urgency equal to "
        "regulated-sector breach readiness (HIPAA / PCI / GDPR-adjacent safeguards)."
    ),
}


def policy_interpretation(source_log: str, risk_level: str, summary: str) -> str:
    """
    Return the specific policy / control framework language associated with this event
    for auditor-facing documentation.
    """
    key = (source_log.strip(), risk_level.strip())
    if key in POLICY_BY_SOURCE_AND_RISK:
        return POLICY_BY_SOURCE_AND_RISK[key]
    rl = risk_level.strip()
    if rl == "Critical":
        return (
            "NIST SP 800-53 — Access Control and Identification & Authentication families; "
            "organizational identity and access policy (CDD/KYC-aligned where applicable)."
        )
    if rl == "High":
        return (
            "NIST Privacy Framework — processing and protection of sensitive data; "
            "NIST AI RMF — governance and mapping of data/AI risk (where automated "
            "processing is in scope)."
        )
    if rl == "Medium":
        return "Organizational security and privacy baseline controls."
    return "Organizational risk management and monitoring controls."


def remediation_action_evidence(resolved: bool, remediation: str) -> str:
    """Plain-language record of prescribed remediation and recorded disposition."""
    text = (remediation or "").strip() or "(No automated remediation text on file.)"
    if resolved:
        return (
            "Disposition: RESOLVED in SentinelView. "
            "Prescribed remediation steps were: "
            f"{text} "
            "Attest completion in your ITSM / GRC system where required by policy."
        )
    return (
        "Disposition: OPEN. "
        "Prescribed organizational response: "
        f"{text} "
        "Follow internal escalation until closed and reflected here."
    )


def close_loop_resolution_summary(row: Mapping[str, Any]) -> str:
    """
    Audit-facing narrative: acknowledgement, resolution time, step performed, notes.
    """
    rem = str(row.get("remediation") or "").strip() or "(No prescribed remediation text.)"
    parts: list[str] = []

    if _row_bool(row.get("acknowledged")):
        at = _format_ts(row.get("acknowledged_at")) or str(row.get("acknowledged_at") or "")
        parts.append(f"Acknowledged: yes (recorded {at})." if at else "Acknowledged: yes.")

    if _row_bool(row.get("resolved")):
        rt = _format_ts(row.get("resolved_at")) or str(row.get("resolved_at") or "")
        parts.append(f"Resolved: yes (recorded {rt})." if rt else "Resolved: yes.")
        step = (row.get("remediation_step_taken") or "").strip()
        if step:
            parts.append(f"Remediation step performed: {step}")
        notes = (row.get("resolution_notes") or "").strip()
        if notes:
            parts.append(f"Resolution notes: {notes}")
    else:
        parts.append("Resolved: no (open).")

    parts.append(f"Prescribed remediation guidance: {rem}")
    return " ".join(parts)


def _format_ts(ts_val: Any) -> str:
    if ts_val is None:
        return ""
    if isinstance(ts_val, float) and math.isnan(ts_val):
        return ""
    if isinstance(ts_val, datetime):
        ts = ts_val
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    s = str(ts_val).strip()
    if not s or s.lower() == "nan":
        return ""
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except ValueError:
        return s


def _row_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def _safe_pdf_text(s: str) -> str:
    """Replace characters that Helvetica cannot encode."""
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "?", s)


def build_compliance_summary_markdown(
    events: Sequence[Mapping[str, Any]],
    *,
    generated_utc: datetime | None = None,
    organization: str = "Organization",
) -> str:
    gen = generated_utc or datetime.now(timezone.utc)
    gen_s = gen.strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = list(events)
    n = len(rows)
    resolved_n = sum(1 for r in rows if _row_bool(r.get("resolved")))

    lines: list[str] = [
        "# SentinelView — Compliance Summary Report",
        "",
        "**Document type:** Security event register and remediation evidence",
        f"**Prepared for:** {organization}",
        f"**Generated (UTC):** {gen_s}",
        f"**Total security events:** {n}",
        f"**Marked resolved in SentinelView:** {resolved_n}",
        f"**Open items:** {n - resolved_n}",
        "",
        "---",
        "",
        "## Purpose",
        "",
        "This report lists every interpreted security event recorded in SentinelView, "
        "the date each finding was detected, the **specific policy / control framework** "
        "the finding is mapped to (including **NIST AI RMF**, **NIST SP 800-53**, and "
        "**CDD/KYC**-aligned identity and data safeguards where applicable), and the "
        "**remediation prescribed** plus **closed-loop response data** "
        "(acknowledgement, resolution, remediation step performed, notes) for "
        "auditor and regulator evidence.",
        "",
        "---",
        "",
        "## Security event register",
        "",
    ]

    if not rows:
        lines.extend(
            [
                "*No security events are present in the export scope.*",
                "",
            ]
        )
        return "\n".join(lines)

    for i, r in enumerate(rows, start=1):
        eid = str(r.get("event_id", ""))
        ts = _format_ts(r.get("ts"))
        risk = str(r.get("risk_level", ""))
        src = str(r.get("source_log", ""))
        summ = str(r.get("summary", ""))
        det = str(r.get("detail", ""))
        rem = str(r.get("remediation", ""))
        policy = policy_interpretation(src, risk, summ)
        action = close_loop_resolution_summary(r)

        lines.extend(
            [
                f"### {i}. Event `{eid}`",
                "",
                f"| Field | Value |",
                f"| --- | --- |",
                f"| **Date detected** | {ts} |",
                f"| **Risk level** | {risk} |",
                f"| **Source log** | {src} |",
                f"| **Finding (summary)** | {summ} |",
                f"| **Finding (detail)** | {det} |",
                f"| **Policy violated (framework mapping)** | {policy} |",
                f"| **Remediation prescribed** | {rem} |",
                f"| **Acknowledged** | {'Yes' if _row_bool(r.get('acknowledged')) else 'No'} |",
                f"| **Acknowledged at (UTC)** | {_format_ts(r.get('acknowledged_at')) or '—'} |",
                f"| **Resolved** | {'Yes' if _row_bool(r.get('resolved')) else 'No'} |",
                f"| **Resolved at (UTC)** | {_format_ts(r.get('resolved_at')) or '—'} |",
                f"| **Remediation step performed** | "
                f"{str(r.get('remediation_step_taken') or '—').replace('|', '/').replace(chr(10), ' ')} |",
                f"| **Resolution notes** | "
                f"{str(r.get('resolution_notes') or '—').replace('|', '/').replace(chr(10), ' ')} |",
                f"| **Closed-loop audit summary** | {action} |",
                f"| **Source file path** | `{r.get('source_path', '')}` |",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "",
            "## Certification block (optional)",
            "",
            "_Prepared from SentinelView automated analysis and operator disposition "
            "records. Signatory, role, and date should be added under local policy._",
            "",
        ]
    )
    return "\n".join(lines)


def _fpdf_output_bytes(pdf: Any) -> bytes:
    out = pdf.output(dest="S")
    if isinstance(out, (bytes, bytearray)):
        return bytes(out)
    return str(out).encode("latin-1")


def build_compliance_summary_pdf(
    events: Sequence[Mapping[str, Any]],
    *,
    generated_utc: datetime | None = None,
    organization: str = "Organization",
) -> bytes:
    """Render the same register as a PDF suitable for attachment to audit workpapers."""
    try:
        from fpdf import FPDF
    except ImportError as e:
        raise ImportError(
            "PDF export requires fpdf2. Install with: pip install fpdf2"
        ) from e

    gen = generated_utc or datetime.now(timezone.utc)
    gen_s = gen.strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = list(events)
    n = len(rows)
    resolved_n = sum(1 for r in rows if _row_bool(r.get("resolved")))

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.multi_cell(0, 8, _safe_pdf_text("SentinelView - Compliance Summary Report"))
    pdf.ln(2)
    pdf.set_font("Helvetica", size=9)
    pdf.multi_cell(
        0,
        5,
        _safe_pdf_text(
            f"Prepared for: {organization}\n"
            f"Generated (UTC): {gen_s}\n"
            f"Total events: {n} | Resolved: {resolved_n} | Open: {n - resolved_n}\n"
            "Purpose: Auditor and regulator evidence of detections, policy mapping, "
            "and remediation disposition."
        ),
    )
    pdf.ln(4)

    if not rows:
        pdf.set_font("Helvetica", "I", 10)
        pdf.multi_cell(0, 6, _safe_pdf_text("No security events in export scope."))
        return _fpdf_output_bytes(pdf)

    for i, r in enumerate(rows, start=1):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 7, _safe_pdf_text(f"{i}. Event {r.get('event_id', '')}"))
        pdf.ln(1)
        pdf.set_font("Helvetica", size=9)

        ts = _format_ts(r.get("ts"))
        risk = str(r.get("risk_level", ""))
        src = str(r.get("source_log", ""))
        summ = str(r.get("summary", ""))
        det = str(r.get("detail", ""))
        rem = str(r.get("remediation", ""))
        sp = str(r.get("source_path", ""))
        policy = policy_interpretation(src, risk, summ)
        action = close_loop_resolution_summary(r)
        ack_at = _format_ts(r.get("acknowledged_at")) or "—"
        res_at = _format_ts(r.get("resolved_at")) or "—"
        step = (r.get("remediation_step_taken") or "").strip() or "—"
        notes = (r.get("resolution_notes") or "").strip() or "—"

        block = (
            f"Date detected: {ts}\n"
            f"Risk level: {risk}\n"
            f"Source log: {src}\n"
            f"Finding (summary): {summ}\n"
            f"Finding (detail): {det}\n\n"
            f"Policy violated (framework mapping):\n{policy}\n\n"
            f"Remediation prescribed:\n{rem}\n\n"
            f"Acknowledged: {'Yes' if _row_bool(r.get('acknowledged')) else 'No'} at {ack_at}\n"
            f"Resolved: {'Yes' if _row_bool(r.get('resolved')) else 'No'} at {res_at}\n"
            f"Remediation step performed: {step}\n"
            f"Resolution notes: {notes}\n\n"
            f"Closed-loop audit summary:\n{action}\n\n"
            f"Source file path: {sp}"
        )
        pdf.multi_cell(0, 5, _safe_pdf_text(block))

    return _fpdf_output_bytes(pdf)
