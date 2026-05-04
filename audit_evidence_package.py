"""
SentinelView — Audit Evidence Package: per-resolution Markdown artifacts and SOC 2 zip export.

Each time an alert is marked resolved (via ``event_db.set_resolution``), a timestamped
Markdown file is written under ``<data_dir>/audit_evidence_packages/``.

The SOC 2 Readiness export bundles those artifacts for external auditors.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from export_report import policy_interpretation

AUDIT_EVIDENCE_SUBDIR = "audit_evidence_packages"


def iso_27001_control_reference(source_log: str, risk_level: str) -> str:
    """
    Illustrative ISO/IEC 27001:2022 Annex A mapping for auditor-facing evidence.
    Complements NIST-oriented ``policy_interpretation``.
    """
    sl = source_log.strip().casefold()
    rl = risk_level.strip().casefold()
    if sl == "access_review" and rl == "critical":
        return (
            "ISO/IEC 27001:2022 — **A.5.15** Access control; **A.5.16** Identity management; "
            "**A.5.18** Access rights (privileged access / least privilege); "
            "**A.8.2** Privileged access rights."
        )
    if sl == "privacy_scan" and rl == "high":
        return (
            "ISO/IEC 27001:2022 — **A.5.33** Protection of records; **A.8.12** Data leakage "
            "prevention; **A.5.34** Privacy and protection of PII; **A.8.8** Management of "
            "technical vulnerabilities (where exposure implies control gaps)."
        )
    if rl == "critical":
        return (
            "ISO/IEC 27001:2022 — **A.5.15** Access control; **A.8.2** Privileged access rights; "
            "**A.5.37** Documented operating procedures."
        )
    if rl == "high":
        return (
            "ISO/IEC 27001:2022 — **A.5.33** Protection of records; **A.8.12** Data leakage "
            "prevention; **A.5.1** Policies for information security."
        )
    if rl == "medium":
        return "ISO/IEC 27001:2022 — **A.5.1** Policies; **A.5.37** Documented operating procedures."
    return "ISO/IEC 27001:2022 — **A.5.24** Information security incident management planning."


def evidence_package_dir(data_dir: Path) -> Path:
    d = Path(data_dir).resolve() / AUDIT_EVIDENCE_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_filename_part(s: str, max_len: int = 48) -> str:
    out = "".join(c if c.isalnum() or c in "-_" else "_" for c in (s or "").strip())
    return (out or "event")[:max_len]


def _canonical_body_for_hash(lines: list[str]) -> str:
    return "\n".join(lines).rstrip() + "\n"


def build_resolved_evidence_markdown(
    row: Mapping[str, Any],
    *,
    attested_by: str | None = None,
    attester_role: str | None = None,
    generator_label: str = "SentinelView",
) -> tuple[str, str]:
    """
    Build Markdown body and SHA-256 integrity digest of the body *before* the integrity block.

    Returns ``(full_markdown, sha256_hex)``.
    """
    eid = str(row.get("event_id", ""))
    ts_raw = str(row.get("ts", ""))
    risk = str(row.get("risk_level", ""))
    src = str(row.get("source_log", ""))
    summ = str(row.get("summary", ""))
    detail = str(row.get("detail", ""))
    prescribed = str(row.get("remediation", "")).strip() or "(None recorded.)"
    resolved_at = str(row.get("resolved_at", ""))
    step = str(row.get("remediation_step_taken", "")).strip() or "—"
    notes = str(row.get("resolution_notes", "")).strip() or "—"
    ack_at = str(row.get("acknowledged_at", "") or "—")
    ack = bool(row.get("acknowledged"))

    nist_iso_block = policy_interpretation(src, risk, summ)
    iso_block = iso_27001_control_reference(src, risk)

    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    signer = (attested_by or "").strip() or "(Not named — system-generated record)"
    role = (attester_role or "").strip() or "—"

    core_lines: list[str] = [
        f"# Audit Evidence Package — Resolved Alert `{eid}`",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| **Evidence generated (UTC)** | {gen_ts} |",
        f"| **Original detection time** | {ts_raw} |",
        f"| **Generator** | {generator_label} |",
        "",
        "---",
        "",
        "## 1. Original risk finding",
        "",
        f"| Attribute | Value |",
        f"| --- | --- |",
        f"| **Risk level** | {risk} |",
        f"| **Source log** | `{src}` |",
        f"| **Summary** | {summ} |",
        f"| **Detail** | {detail} |",
        f"| **Prescribed remediation (at detection)** | {prescribed} |",
        "",
        "---",
        "",
        "## 2. Control mapping (NIST / ISO 27001)",
        "",
        "### NIST-oriented interpretation",
        "",
        nist_iso_block,
        "",
        "### ISO/IEC 27001:2022 (Annex A — illustrative)",
        "",
        iso_block,
        "",
        "---",
        "",
        "## 3. Plain English remediation performed",
        "",
        "The operator closed this alert in SentinelView with the following disposition.",
        "",
        f"| Field | Value |",
        f"| --- | --- |",
        f"| **Resolved at (UTC)** | {resolved_at} |",
        f"| **Remediation step performed** | {step} |",
        f"| **Resolution notes** | {notes} |",
        f"| **Acknowledged** | {'Yes' if ack else 'No'} |",
        f"| **Acknowledged at** | {ack_at} |",
        "",
        "---",
        "",
        "## 4. Digital signature & approval log",
        "",
        "This section provides a non-repudiation-oriented **attestation trail** suitable "
        "for SOC 2 and ISO 27001 evidence folders. It does not replace organizational PKI or "
        "qualified electronic signatures where legally required.",
        "",
        "| Approval log entry | Value |",
        "| --- | --- |",
        f"| **Attested by** | {signer} |",
        f"| **Role / title** | {role} |",
        f"| **Resolution recorded at (UTC)** | {resolved_at} |",
        f"| **System of record** | SentinelView (`event_id`: `{eid}`) |",
        "",
        "**Operator attestation:** By marking this finding resolved, the organization records "
        "that the remediation step above was performed per internal policy.",
        "",
    ]

    body_for_hash = _canonical_body_for_hash(core_lines)
    digest = hashlib.sha256(body_for_hash.encode("utf-8")).hexdigest()

    trailer = [
        "---",
        "",
        "### Integrity reference",
        "",
        f"**SHA-256** (UTF-8 body through “Operator attestation” above, excluding this section):",
        "",
        f"`{digest}`",
        "",
        "*To verify: concatenate bytes of that Markdown prefix and compute SHA-256.*",
        "",
    ]

    full_md = body_for_hash.rstrip() + "\n" + "\n".join(trailer) + "\n"
    return full_md, digest


def resolved_evidence_filename(row: Mapping[str, Any]) -> str:
    """Stable, filesystem-safe name derived from event id and resolution time."""
    eid = _safe_filename_part(str(row.get("event_id", "unknown")))
    ra = str(row.get("resolved_at", "") or datetime.now(timezone.utc).isoformat())
    ts = ra.replace(":", "").replace("+00:00", "Z").replace("-", "")[:17]
    return f"ResolvedEvidence_{eid}_{ts}.md"


def write_resolved_event_evidence(
    row: Mapping[str, Any],
    data_dir: Path,
    *,
    attested_by: str | None = None,
    attester_role: str | None = None,
) -> Path:
    """
    Write the audit evidence Markdown file for one resolved event.
    Returns path written.
    """
    full_md, _digest = build_resolved_evidence_markdown(
        row,
        attested_by=attested_by,
        attester_role=attester_role,
    )
    out_dir = evidence_package_dir(data_dir)
    fname = resolved_evidence_filename(row)
    out_path = out_dir / fname
    out_path.write_text(full_md, encoding="utf-8")
    return out_path


def list_resolved_evidence_files(data_dir: Path) -> list[Path]:
    """All ``*.md`` artifacts in the audit evidence folder."""
    d = evidence_package_dir(data_dir)
    if not d.is_dir():
        return []
    return sorted(d.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)


def create_soc2_readiness_zip_bytes(
    data_dir: Path,
    *,
    organization: str = "Organization",
) -> tuple[bytes, str]:
    """
    Zip every resolved-evidence Markdown file plus a manifest and README for auditors.

    Returns ``(zip_bytes, suggested_filename)``.
    """
    files = list_resolved_evidence_files(data_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_org = "".join(c if c.isalnum() or c in "-_" else "_" for c in organization.strip())[
        :48
    ] or "Organization"
    zip_name = f"SentinelView_SOC2_Readiness_{safe_org}_{stamp}.zip"

    manifest = {
        "package": "SentinelView SOC 2 / ISO 27001 readiness evidence",
        "organization": organization,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_count": len(files),
        "artifacts": [p.name for p in files],
        "notes": (
            "Contains per-resolution Markdown packages generated when alerts were marked "
            "resolved in SentinelView. Each file includes NIST and ISO 27001 mappings, "
            "remediation disposition, and SHA-256 integrity reference."
        ),
    }

    readme = "\n".join(
        [
            "# SentinelView — SOC 2 Readiness Evidence Package",
            "",
            f"**Prepared for:** {organization}",
            f"**Generated (UTC):** {manifest['generated_utc']}",
            "",
            "## Contents",
            "",
            "- `MANIFEST.json` — inventory of bundled Markdown evidence files.",
            "- `README_AUDITOR.md` — this file.",
            "- `ResolvedEvidence_*.md` — one file per resolved security event.",
            "",
            "Each Markdown file documents the original finding, control mapping, remediation "
            "steps performed, and an approval / integrity section.",
            "",
        ]
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))
        zf.writestr("README_AUDITOR.md", readme)
        for p in files:
            zf.write(p, arcname=f"evidence/{p.name}")

    return buf.getvalue(), zip_name
