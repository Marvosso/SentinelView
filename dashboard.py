"""
SentinelView — Streamlit GRC dashboard (Windows-first).
Run from project root:  streamlit run dashboard.py

**Multi-client:** pick a tenant under **Client** — each uses ``clients/<name>/data`` (SQLite)
and ``clients/<name>/logs`` (CSV ingestion). **Client Onboarding Wizard** writes ``client_profile.json`` (org + risk profile); the dashboard reads it for
profile-aware headers (risk-weighted urgency), **SOC 2** sidebar progress when selected, **HIPAA** labels in Evidence Library, and the **Business context** card. **Onboarding**
writes ``client_policy.json`` for SIEM tuning; **Policy Generator** builds policy PDFs from that profile.
**Global Risk (Admin)** aggregates all clients. Optional **Custom event data
folder** overrides ``data/`` for legacy layouts.
"""

from __future__ import annotations

import html
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from audit_evidence_package import (
    create_soc2_readiness_zip_bytes,
    list_resolved_evidence_files,
)
from client_profile import (
    COMPLIANCE_GOAL_OPTIONS,
    DATA_TYPE_OPTIONS,
    INDUSTRY_VERTICALS,
    SYSTEM_ENVIRONMENT_OPTIONS,
    build_client_profile_document,
    business_context_message,
    load_client_profile,
    write_client_profile_file,
)
from onboarding_wizard_state import clear_wizard_state, load_wizard_state, save_wizard_state
from policy_generation_engine import generate_data_handling_policy_engine
from client_workspace import (
    GLOBAL_CLIENT_LABEL,
    build_global_risk_summary,
    clients_root,
    ensure_client_layout,
    list_registered_clients,
)
from onboarding_policy import (
    BUSINESS_TYPES,
    DATA_SENSITIVITY_OPTIONS,
    REGULATORY_OPTIONS,
    WORKFORCE_OPTIONS,
    client_policy_path_for_client,
    compute_alert_profile,
    load_client_policy,
    write_client_policy_file,
)
from policy_evidence_bridge import render_policy_evidence_bridge
from policy_generation_engine import (
    generate_policies_from_client_profile,
    policies_engine_markdown_bundle,
)
from policy_generator import build_policies_pdf_bytes
from event_db import (
    default_data_dir,
    init_db,
    load_events_rows,
    set_acknowledged,
    set_resolution,
)
from export_report import (
    build_compliance_summary_markdown,
    build_compliance_summary_pdf,
    close_loop_resolution_summary,
    policy_interpretation,
)
from remediation import REMEDIATION_BY_RISK_TYPE, remediation_for
from response_tracking import remediation_step_choices, widget_key_safe
from settings_loader import load_settings, save_settings, settings_from_form_lines
from trust_center_ui import (
    inject_trust_center_theme,
    render_actionable_alert_feed,
    render_audit_ready_hero,
    render_sidebar_managed_footer,
)

# High-contrast palette for owners (WCAG-friendly direction).
COLOR_CRITICAL_BG = "#fecaca"
COLOR_CRITICAL_FG = "#7f1d1d"
COLOR_HIGH_BG = "#fef08a"
COLOR_HIGH_FG = "#854d0e"
COLOR_GOOD_BG = "#bbf7d0"
COLOR_GOOD_FG = "#14532d"
COLOR_WARN_BG = "#fde047"
COLOR_NEUTRAL = "#1e293b"


def _suggested_event_data_dir() -> Path:
    inbox = Path.cwd() / "ingest_inbox" / "sentinelview_data"
    if inbox.is_dir():
        return inbox
    return default_data_dir()


def _file_path_from_context(context_json: str) -> str:
    try:
        d = json.loads(context_json)
        return str(d.get("File_Path", "") or "")
    except (json.JSONDecodeError, TypeError):
        return ""


def _privacy_system_volume(file_path: str) -> str:
    """Bucket paths into a short volume/folder label for the heatmap (Windows paths)."""
    raw = (file_path or "").strip()
    if not raw:
        return "Unknown"
    p = Path(raw.replace("/", "\\"))
    parts = p.parts
    if not parts:
        return "Unknown"
    root = parts[0]
    if root.startswith("\\\\"):
        return f"{root}\\{parts[1]}" if len(parts) > 1 else root
    if len(parts) >= 2:
        return f"{root}{parts[1]}"
    return root


def _load_df(data_dir: Path) -> pd.DataFrame:
    init_db(data_dir)
    rows = load_events_rows(data_dir)
    if not rows:
        return pd.DataFrame(
            columns=[
                "event_id",
                "ts",
                "risk_level",
                "summary",
                "detail",
                "source_log",
                "source_path",
                "context_json",
                "remediation",
                "resolved",
                "dedupe_key",
                "acknowledged",
                "acknowledged_at",
                "resolved_at",
                "remediation_step_taken",
                "resolution_notes",
            ]
        )
    return pd.DataFrame(rows)


@st.cache_data(ttl=3)
def load_events_df(path_str: str) -> pd.DataFrame:
    return _load_df(Path(path_str))


@st.cache_data(ttl=3)
def load_global_risk_data(workspace_root_str: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Cached aggregate across all client workspaces (``clients/*/data`` under this root)."""
    return build_global_risk_summary(Path(workspace_root_str))


def _compliance_score(df: pd.DataFrame) -> tuple[float | None, int, int]:
    n = len(df)
    if n == 0:
        return None, 0, 0
    resolved = int(df["resolved"].sum())
    unresolved = n - resolved
    return 100.0 * resolved / n, resolved, unresolved


def _row_resolved(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def _open_events_mask(df: pd.DataFrame) -> pd.Series:
    """Unresolved findings."""
    if df.empty or "resolved" not in df.columns:
        return pd.Series([], dtype=bool)
    return ~df["resolved"].map(_row_resolved)


def dashboard_header_posture(
    df: pd.DataFrame,
    *,
    client_risk_profile: str | None,
) -> tuple[str, str]:
    """
    Visual urgency for the top banner: ``red`` | ``amber`` | ``neutral``.

    When ``client_profile.json`` marks inherent risk **High**, access-control findings at
    **High** severity are promoted to the same urgency as Critical for header coloring.
    """
    if df.empty:
        return (
            "neutral",
            "No events ingested yet — the posture strip activates after "
            "<strong>ingest_engine</strong> runs.",
        )
    open_df = df[_open_events_mask(df)]
    if open_df.empty:
        return "neutral", "No open findings — disposition is current."

    if (open_df["risk_level"] == "Critical").any():
        return (
            "red",
            "Open <strong>Critical</strong> findings — immediate leadership and IR engagement.",
        )

    rp = (client_risk_profile or "").strip()
    if rp == "High":
        ar = open_df[open_df["source_log"] == "access_review"]
        elevated = ar[ar["risk_level"].isin(["High", "Critical"])]
        if not elevated.empty:
            return (
                "red",
                "Risk profile <strong>High</strong> — open <strong>access review</strong> items "
                "at High/Critical are treated as top-tier (stricter threshold).",
            )
        summ = ar["summary"].astype(str).str.lower()
        if len(summ) and summ.str.contains(
            "roster|unauthorized|privileged|admin", regex=True
        ).any():
            return (
                "red",
                "Risk profile <strong>High</strong> — open <strong>access</strong> findings "
                "match elevated sensitivity.",
            )

    if (open_df["risk_level"] == "High").any():
        return (
            "amber",
            "Open <strong>High</strong> findings — prioritize remediation and closure.",
        )

    return "amber", "Open Medium or lower items — continue triage toward zero backlog."


def _open_critical_equivalent_count(
    df: pd.DataFrame,
    client_risk_profile: str | None,
) -> int:
    """Open Critical plus access-review High when inherent risk profile is High."""
    if df.empty:
        return 0
    df = df.copy()
    df["_open"] = _open_events_mask(df)
    o = df[df["_open"]]
    n = int((o["risk_level"] == "Critical").sum())
    if (client_risk_profile or "").strip() == "High":
        n += int(
            ((o["source_log"] == "access_review") & (o["risk_level"] == "High")).sum()
        )
    return n


def _render_dashboard_banner(posture: str, detail_md: str) -> None:
    """High-contrast posture strip under organization branding."""
    if posture == "red":
        bg, border, fg = "#fecaca", "#b91c1c", "#450a0a"
        title = "Elevated alert posture"
    elif posture == "amber":
        bg, border, fg = "#fef9c3", "#ca8a04", "#713f12"
        title = "Attention recommended"
    else:
        bg, border, fg = "#e2e8f0", "#64748b", "#334155"
        title = "Posture overview"

    st.markdown(
        f"""
        <div style="background:{bg};border:2px solid {border};border-radius:8px;padding:0.65rem 1rem;
          margin-bottom:0.75rem;color:{fg};font-weight:600;font-size:0.9rem;">
          <span style="font-weight:800;text-transform:uppercase;letter-spacing:0.06em;font-size:0.72rem;
            display:block;margin-bottom:0.35rem;">{html.escape(title)}</span>
          <span style="font-weight:600;">{detail_md}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_profile_aware_heading(
    *,
    display_org: str,
    profile: dict[str, object] | None,
    df: pd.DataFrame,
    client_risk_profile: str | None,
) -> None:
    """Organization banner, dynamic risk strip, and business-context card."""
    safe_org = html.escape((display_org or "").strip() or "Organization")
    st.markdown(
        f"""
        <div style="margin-bottom:0.35rem;">
          <span style="font-size:1.65rem;font-weight:800;color:#0f172a;letter-spacing:-0.02em;">{safe_org}</span>
          <span style="display:block;font-size:0.8rem;color:#64748b;font-weight:600;margin-top:0.2rem;
            text-transform:uppercase;letter-spacing:0.05em;">SentinelView</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    posture, msg = dashboard_header_posture(df, client_risk_profile=client_risk_profile)
    _render_dashboard_banner(posture, msg)
    st.markdown("##### Business context")
    st.info(business_context_message(profile))
    st.caption(
        "Alert tables use **Critical** (red), **High** (amber), and lower tiers (green) "
        "based on each row’s stored severity."
    )


def render_global_override_heading(df: pd.DataFrame, report_org: str) -> None:
    """Banner + org line when using Global + custom data folder (no client_profile.json)."""
    safe = html.escape((report_org or "").strip() or "Organization")
    st.markdown(
        f"""
        <div style="margin-bottom:0.35rem;">
          <span style="font-size:1.65rem;font-weight:800;color:#0f172a;">{safe}</span>
          <span style="display:block;font-size:0.8rem;color:#64748b;font-weight:600;">Organization (reports)</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    posture, msg = dashboard_header_posture(df, client_risk_profile=None)
    _render_dashboard_banner(posture, msg)
    st.caption(
        "Using a **custom event folder** under Global — select a **named client** to apply "
        "**client_profile.json** (risk weighting, SOC 2 sidebar, HIPAA evidence labels)."
    )


def _framework_readiness(
    df: pd.DataFrame, compliance_pct: float | None
) -> tuple[float, float]:
    """SOC 2–style and ISO 27001–style readiness indices derived from stored events."""
    if df.empty or compliance_pct is None:
        return 0.0, 0.0
    df = df.copy()
    df["_res"] = df["resolved"].map(_row_resolved)
    crit_open = df[(df["risk_level"] == "Critical") & (~df["_res"])]
    high_open = df[(df["risk_level"] == "High") & (~df["_res"])]
    med_open = df[(df["risk_level"] == "Medium") & (~df["_res"])]

    soc2 = compliance_pct - min(35, len(crit_open) * 18) - min(15, len(high_open) * 4)
    iso = compliance_pct - min(30, len(high_open) * 10) - min(10, len(med_open) * 2)
    return max(0.0, min(100.0, soc2)), max(0.0, min(100.0, iso))


def _badge_html(label: str, kind: str) -> str:
    if kind == "pass":
        bg, fg, border = "#166534", "#ffffff", "#14532d"
    elif kind == "fail":
        bg, fg, border = "#b91c1c", "#ffffff", "#7f1d1d"
    else:
        bg, fg, border = "#c2410c", "#ffffff", "#9a3412"
    return (
        f'<span style="display:inline-block;padding:6px 14px;border-radius:6px;'
        f"background:{bg};color:{fg};font-weight:800;font-size:0.85rem;"
        f'letter-spacing:0.02em;border:2px solid {border};">{label}</span>'
    )


def _active_control_badges(df: pd.DataFrame) -> list[tuple[str, str]]:
    """Labels and badge kind: pass | fail | action."""
    out: list[tuple[str, str]] = []
    if df.empty:
        out.append(("Access review monitoring", "action"))
        out.append(("Sensitive data & PII exposure monitoring", "action"))
        out.append(("Incident response disposition", "action"))
        return out

    df = df.copy()
    df["_res"] = df["resolved"].map(_row_resolved)
    ar = df[df["source_log"] == "access_review"]
    ps = df[df["source_log"] == "privacy_scan"]
    crit_ar = ar[(ar["risk_level"] == "Critical") & (~ar["_res"])]
    high_ps = ps[(ps["risk_level"] == "High") & (~ps["_res"])]
    open_any = len(df[~df["_res"]]) > 0

    if len(crit_ar) == 0:
        out.append(("Privileged / Admin access alignment", "pass"))
    else:
        out.append(("Privileged / Admin access alignment", "fail"))

    if len(high_ps) == 0:
        out.append(("PII & public-path exposure controls", "pass"))
    else:
        out.append(("PII & public-path exposure controls", "fail"))

    if not open_any:
        out.append(("Closed-loop remediation evidence", "pass"))
    elif len(df[~df["_res"]]) <= 3:
        out.append(("Closed-loop remediation evidence", "action"))
    else:
        out.append(("Closed-loop remediation evidence", "fail"))
    return out


MONITORED_CONTROLS: list[dict[str, str]] = [
    {
        "id": "SV-AC-01",
        "name": "User Access Reviews",
        "category": "Access Control",
        "source_log": "access_review",
        "risk_gate": "Critical",
    },
    {
        "id": "SV-PR-01",
        "name": "Sensitive Data Protection",
        "category": "Privacy & Encryption",
        "source_log": "privacy_scan",
        "risk_gate": "High",
    },
    {
        "id": "SV-OP-01",
        "name": "Security Event Review & Disposition",
        "category": "Operations",
        "source_log": "*",
        "risk_gate": "any_open",
    },
]


def _control_row_status(
    df: pd.DataFrame,
    spec: dict[str, str],
    *,
    client_risk_profile: str | None = None,
) -> tuple[str, str, int]:
    """Returns status label, css-ish category for buttons, count of failing findings."""
    if df.empty:
        return "No data", "neutral", 0

    df = df.copy()
    df["_res"] = df["resolved"].map(_row_resolved)
    src = spec["source_log"]
    gate = spec["risk_gate"]
    rp = (client_risk_profile or "").strip()

    if gate == "any_open":
        open_n = len(df[~df["_res"]])
        if open_n == 0:
            return "Passing", "pass", 0
        return "Failing", "fail", open_n

    sub = df[df["source_log"] == src]
    if sub.empty:
        return "Passing", "pass", 0
    if gate == "Critical":
        if rp == "High" and src == "access_review":
            bad = sub[
                (sub["risk_level"].isin(["Critical", "High"]))
                & (~sub["_res"])
            ]
        else:
            bad = sub[(sub["risk_level"] == "Critical") & (~sub["_res"])]
    elif gate == "High":
        bad = sub[(sub["risk_level"] == "High") & (~sub["_res"])]
    else:
        bad = sub[~sub["_res"]]

    n = len(bad)
    if n == 0:
        return "Passing", "pass", 0
    return "Failing", "fail", n


def _sop_markdown_for_control(spec: dict[str, str]) -> str:
    """Plain-English SOP text for auditors and operators."""
    sid = spec["id"]
    lines: list[str] = [
        f"### {spec['name']} (`{sid}`)",
        "",
        "Follow these steps when this control is **Failing**. Align actions with your "
        "internal change and incident processes.",
        "",
    ]
    if spec["source_log"] == "access_review":
        lines.extend(
            [
                "1. **Contain:** Disable or revoke credentials for the affected identifier "
                "and confirm no active privileged sessions remain abnormal.",
                "2. **Verify:** Compare `access_review` findings against your HR / "
                "authoritative roster and provisioning records.",
                "3. **Record:** Open or update an ITSM / GRC ticket with owner, scope, "
                "and target completion date.",
                "4. **Evidence:** When resolved, use *Mark as Resolved* in SentinelView "
                "with the remediation step performed.",
                "",
                f"**Automated guidance:** {REMEDIATION_BY_RISK_TYPE.get('Critical Access Risk', remediation_for('Critical', 'access_review'))}",
                "",
                "**Suggested resolution codes (pick one when closing):**",
            ]
        )
        for opt in remediation_step_choices("access_review", "Critical"):
            lines.append(f"- {opt}")
    elif spec["source_log"] == "privacy_scan":
        lines.extend(
            [
                "1. **Isolate:** Move affected content out of public or broadly shared "
                "locations into an approved secure vault or restricted library.",
                "2. **Permissions:** Remove inheritance / Everyone-type access; enforce "
                "least-privilege share and NTFS permissions.",
                "3. **PII handling:** Redact, delete, or relocate data per retention and "
                "privacy policy.",
                "4. **Evidence:** Close the loop in SentinelView with disposition notes "
                "for auditors.",
                "",
                f"**Automated guidance:** {REMEDIATION_BY_RISK_TYPE.get('High Privacy Risk', remediation_for('High', 'privacy_scan'))}",
                "",
                "**Suggested resolution codes:**",
            ]
        )
        for opt in remediation_step_choices("privacy_scan", "High"):
            lines.append(f"- {opt}")
    else:
        lines.extend(
            [
                "1. Triage open events by risk (Critical → High → Medium).",
                "2. Assign owners and due dates in your GRC or ITSM tool.",
                "3. For each item, apply the prescribed remediation text on the alert.",
                "4. Export the Compliance Summary for auditor review when milestones close.",
            ]
        )
    return "\n".join(lines)


def _build_evidence_slice_markdown(
    records: list[dict[str, object]],
    *,
    title: str,
    organization: str,
) -> str:
    gen_ts = datetime.now(timezone.utc)
    gen_s = gen_ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [
        f"# {title}",
        "",
        "**Document type:** SentinelView automated evidence export",
        f"**Prepared for:** {organization}",
        f"**Generated (UTC):** {gen_s}",
        f"**Rows included:** {len(records)}",
        "",
        "---",
        "",
    ]
    for i, r in enumerate(records, start=1):
        eid = str(r.get("event_id", ""))
        ts = str(r.get("ts", ""))
        risk = str(r.get("risk_level", ""))
        src = str(r.get("source_log", ""))
        summ = str(r.get("summary", ""))
        pol = policy_interpretation(src, risk, summ)
        loop = close_loop_resolution_summary(r)
        lines.extend(
            [
                f"## {i}. Event `{eid}`",
                "",
                f"| Field | Value |",
                f"| --- | --- |",
                f"| **Date detected** | {ts} |",
                f"| **Risk** | {risk} |",
                f"| **Source** | {src} |",
                f"| **Summary** | {summ} |",
                f"| **Framework mapping** | {pol} |",
                f"| **Disposition** | {loop} |",
                "",
            ]
        )
    return "\n".join(lines)


@st.dialog("Plain English SOPs — SentinelView", width="large")
def _grc_remediation_dialog() -> None:
    spec = st.session_state.get("_sv_grc_sop_spec")
    if not spec:
        st.warning("No control selected.")
        return
    st.markdown(_sop_markdown_for_control(spec))


def _style_alerts_table(
    df: pd.DataFrame, risk_column: str = "risk_level"
) -> pd.io.formats.style.Styler:
    def _risk_colors(s: pd.Series) -> list[str]:
        out: list[str] = []
        for v in s:
            if v == "Critical":
                out.append(
                    f"background-color: {COLOR_CRITICAL_BG}; color: {COLOR_CRITICAL_FG}; "
                    "font-weight: 700;"
                )
            elif v == "High":
                out.append(
                    f"background-color: {COLOR_HIGH_BG}; color: {COLOR_HIGH_FG}; "
                    "font-weight: 700;"
                )
            elif v == "Medium":
                out.append(
                    f"background-color: {COLOR_WARN_BG}; color: {COLOR_NEUTRAL}; font-weight: 600;"
                )
            else:
                out.append(
                    f"background-color: {COLOR_GOOD_BG}; color: {COLOR_GOOD_FG}; font-weight: 600;"
                )
        return out

    view = df.copy()
    return view.style.apply(_risk_colors, subset=[risk_column]).hide(axis="index")


def render_trust_center_tab(
    df: pd.DataFrame,
    data_dir: Path,
    report_org: str,
    *,
    client_risk_profile: str | None = None,
    client_id: str | None = None,
) -> None:
    """Security & Compliance Overview (SMB-friendly); internal route key remains Trust Center."""
    from security_overview_ui import render_security_compliance_overview

    score, n_res, n_unres = _compliance_score(df)
    soc2, iso = _framework_readiness(df, score)
    badges = _active_control_badges(df)
    profile = load_client_profile(client_id) if client_id else None
    pol_path = client_policy_path_for_client(client_id) if client_id else None
    has_policy_file = bool(pol_path and pol_path.is_file())
    render_security_compliance_overview(
        df=df,
        data_dir=data_dir,
        report_org=report_org,
        client_risk_profile=client_risk_profile,
        client_id=client_id,
        score=score,
        n_res=n_res,
        n_unres=n_unres,
        soc2=soc2,
        iso=iso,
        badges=badges,
        n_controls=len(MONITORED_CONTROLS),
        profile=profile,
        has_policy_file=has_policy_file,
        load_events_df_clear=load_events_df.clear,
    )


def render_control_monitoring_tab(
    df: pd.DataFrame,
    _data_dir: Path,
    *,
    client_risk_profile: str | None = None,
) -> None:
    """Tab 2 — operational controls table + remediation SOP dialog."""
    st.caption(
        "Live view of monitored controls. **Remediate** opens plain-English SOPs aligned "
        "with SentinelView playbooks."
    )
    if (client_risk_profile or "").strip() == "High":
        st.caption(
            "_Access reviews_: with inherent risk **High**, open **High** severity access "
            "findings count toward the same control gate as **Critical**."
        )

    rows_out: list[dict[str, object]] = []
    for spec in MONITORED_CONTROLS:
        status, _cat, n_fail = _control_row_status(
            df,
            spec,
            client_risk_profile=client_risk_profile,
        )
        last_ev = "—"
        if not df.empty and spec["source_log"] != "*":
            sub = df[df["source_log"] == spec["source_log"]]
            if not sub.empty:
                last_ev = str(sub["ts"].max())[:19]
        elif not df.empty and spec["source_log"] == "*":
            last_ev = str(df["ts"].max())[:19]

        rows_out.append(
            {
                "Control ID": spec["id"],
                "Control": spec["name"],
                "Category": spec["category"],
                "Status": status,
                "Open findings": n_fail if spec["risk_gate"] != "any_open" else n_fail,
                "Last evidence (UTC)": last_ev,
            }
        )

    table_df = pd.DataFrame(rows_out)
    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        height=min(220, 60 + 48 * len(table_df)),
    )

    st.divider()
    st.markdown("##### Controls requiring action")
    any_fail = False
    for spec in MONITORED_CONTROLS:
        status, _c, n_fail = _control_row_status(
            df,
            spec,
            client_risk_profile=client_risk_profile,
        )
        if status != "Failing":
            continue
        any_fail = True
        with st.container():
            c1, c2 = st.columns([4, 1])
            with c1:
                st.markdown(
                    f"**{spec['name']}** (`{spec['id']}`) · "
                    f"{n_fail} open item(s) · _{spec['category']}_"
                )
            with c2:
                if st.button(
                    "Remediate",
                    key=f"rem_btn_{spec['id']}",
                    type="primary",
                ):
                    st.session_state["_sv_grc_sop_spec"] = spec
                    _grc_remediation_dialog()

    if not any_fail:
        st.success("No failing controls — operational posture matches current evidence.")


def render_evidence_library_tab(
    df: pd.DataFrame,
    data_dir: Path,
    report_org: str,
    *,
    hipaa_labels: bool = False,
) -> None:
    """Tab 3 — evidence register with per-item auditor downloads."""
    st.caption(
        "Automated evidence items derived from ingestion timestamps and event registers."
    )
    if hipaa_labels:
        st.caption(
            "_HIPAA view_: section titles and descriptions use **HIPAA Security Rule** "
            "safeguard labels (illustrative mapping for auditors — not legal advice)."
        )
        st.markdown("##### HIPAA safeguard-oriented exports")
        zip_caption = (
            "Bundle of **Audit Evidence Package** Markdown files when alerts resolve — "
            "mapped below to Administrative / Technical safeguards. Stored under "
            "`audit_evidence_packages` in your event data folder."
        )
        zip_btn = "Export HIPAA evidence bundle (ZIP)"
    else:
        st.markdown("##### SOC 2 readiness export")
        zip_caption = (
            "Zip archive of every **Audit Evidence Package** (Markdown) written when an alert "
            "is marked resolved — stored under `audit_evidence_packages` in your event data folder."
        )
        zip_btn = "Export SOC 2 Readiness Report (ZIP)"
    st.caption(zip_caption)
    n_pkg = len(list_resolved_evidence_files(data_dir))
    zip_bytes, zip_fname = create_soc2_readiness_zip_bytes(
        data_dir, organization=report_org.strip() or "Organization"
    )
    z1, z2 = st.columns([1, 2])
    with z1:
        if hipaa_labels:
            st.metric("Resolved safeguard evidence files (Markdown)", n_pkg)
        else:
            st.metric("Resolved evidence files on disk", n_pkg)
    with z2:
        st.download_button(
            label=zip_btn,
            data=zip_bytes,
            file_name=zip_fname,
            mime="application/zip",
            type="primary",
            use_container_width=True,
            key="sv_export_soc2_zip",
        )
    st.divider()

    gen_ts = datetime.now(timezone.utc)
    stamp = gen_ts.strftime("%Y%m%d_%H%M%S")
    safe_org = re.sub(r"[^\w\-.]+", "_", report_org.strip() or "Organization")[:48]

    items: list[tuple[str, str, bytes, str, str]] = []
    # (title, filename_suffix, data bytes, mime, description)

    if not df.empty:
        ar = df[df["source_log"] == "access_review"]
        if not ar.empty:
            d = str(ar["ts"].max())[:10]
            recs = ar.sort_values("ts", ascending=False).to_dict("records")
            ar_title = (
                f"[Administrative safeguards — Access mgmt] Access review evidence — {d}"
                if hipaa_labels
                else f"Weekly Access Review Log — {d}"
            )
            md = _build_evidence_slice_markdown(
                recs,
                title=ar_title,
                organization=report_org,
            )
            ar_desc = (
                "HIPAA: **Administrative safeguards** — information access management "
                "(illustrative); access-review channel with disposition."
                if hipaa_labels
                else "Access review channel findings with framework mapping and disposition."
            )
            items.append(
                (
                    ar_title,
                    f"Evidence_AccessReview_{safe_org}_{stamp}.md",
                    md.encode("utf-8"),
                    "text/markdown",
                    ar_desc,
                )
            )
        ps = df[df["source_log"] == "privacy_scan"]
        if not ps.empty:
            d = str(ps["ts"].max())[:10]
            recs = ps.sort_values("ts", ascending=False).to_dict("records")
            ps_title = (
                f"[Technical safeguards — Access control] Privacy & exposure evidence — {d}"
                if hipaa_labels
                else f"Privacy & Data Scan Evidence — {d}"
            )
            md = _build_evidence_slice_markdown(
                recs,
                title=ps_title,
                organization=report_org,
            )
            ps_desc = (
                "HIPAA: **Technical safeguards** — access control & transmission hygiene "
                "(illustrative); PII / exposure-oriented findings."
                if hipaa_labels
                else "Privacy scan channel findings (PII / exposure posture)."
            )
            items.append(
                (
                    ps_title,
                    f"Evidence_PrivacyScan_{safe_org}_{stamp}.md",
                    md.encode("utf-8"),
                    "text/markdown",
                    ps_desc,
                )
            )

    if not df.empty:
        all_recs = df.sort_values("ts", ascending=True).to_dict("records")
        full_md = build_compliance_summary_markdown(
            all_recs,
            generated_utc=gen_ts,
            organization=report_org.strip() or "Organization",
        )
        try:
            pdf_bytes = build_compliance_summary_pdf(
                all_recs,
                generated_utc=gen_ts,
                organization=report_org.strip() or "Organization",
            )
        except ImportError:
            pdf_bytes = None
        full_title = (
            f"[Administrative safeguards — Audit controls] Full compliance register — {stamp[:8]}"
            if hipaa_labels
            else f"Full compliance register — {stamp[:8]}"
        )
        full_desc = (
            "HIPAA: **Administrative safeguards** — audit controls, documentation, and "
            "closed-loop disposition (illustrative register)."
            if hipaa_labels
            else "Complete event register with policy mapping (Markdown)."
        )
        items.append(
            (
                full_title,
                f"SentinelView_Compliance_Summary_{safe_org}_{stamp}.md",
                full_md.encode("utf-8"),
                "text/markdown",
                full_desc,
            )
        )
        if pdf_bytes:
            pdf_title = (
                f"[Administrative safeguards — Audit controls] Full register (PDF) — {stamp[:8]}"
                if hipaa_labels
                else f"Full compliance register (PDF) — {stamp[:8]}"
            )
            pdf_desc = (
                "HIPAA-oriented PDF register for auditors (illustrative mapping)."
                if hipaa_labels
                else "Auditor-ready PDF register."
            )
            items.append(
                (
                    pdf_title,
                    f"SentinelView_Compliance_Summary_{safe_org}_{stamp}.pdf",
                    pdf_bytes,
                    "application/pdf",
                    pdf_desc,
                )
            )

    if not items:
        st.info(
            "No evidence packages yet. After **ingest_engine** records events, automated "
            "line items appear here."
        )
        return

    for i, (title, fname, raw, mime, desc) in enumerate(items):
        with st.container():
            e1, e2 = st.columns([3, 1])
            with e1:
                st.markdown(f"**{title}**")
                st.caption(desc)
            with e2:
                st.download_button(
                    label="Download for auditor",
                    data=raw,
                    file_name=fname,
                    mime=mime,
                    type="primary",
                    use_container_width=True,
                    key=f"sv_ev_{i}_{fname[:24]}",
                )
            st.divider()


def render_onboarding_tab(client_id: str) -> None:
    """Streamlit onboarding wizard — writes ``clients/<id>/client_policy.json``."""
    st.caption(
        "Profile drives **alert sensitivity** (especially PII-in-public-path severity) "
        "merged with `settings.yaml` at analysis time."
    )
    ensure_client_layout(client_id)
    existing = load_client_policy(client_id)

    sens_label_to_id = {lab: sid for lab, sid in DATA_SENSITIVITY_OPTIONS}
    reg_label_to_id = {lab: sid for lab, sid in REGULATORY_OPTIONS}

    bt_default_idx = 0
    if existing and existing.get("business_type") in BUSINESS_TYPES:
        bt_default_idx = BUSINESS_TYPES.index(str(existing["business_type"]))

    default_sens_labels = []
    if existing and isinstance(existing.get("data_sensitivity"), list):
        rev = {sid: lab for lab, sid in DATA_SENSITIVITY_OPTIONS}
        for sid in existing["data_sensitivity"]:
            if sid in rev:
                default_sens_labels.append(rev[sid])

    default_reg_labels = []
    if existing and isinstance(existing.get("regulatory_targets"), list):
        rev_r = {sid: lab for lab, sid in REGULATORY_OPTIONS}
        for sid in existing["regulatory_targets"]:
            if sid in rev_r:
                default_reg_labels.append(rev_r[sid])

    business_type = st.selectbox(
        "Business type",
        BUSINESS_TYPES,
        index=bt_default_idx,
        help="Vertical informs baseline SIEM sensitivity (e.g. FinTech elevates PII-in-public to Critical).",
    )
    sens_labels = st.multiselect(
        "Data sensitivity",
        options=list(sens_label_to_id.keys()),
        default=default_sens_labels,
        help="What classes of data you typically store or process.",
    )
    reg_labels = st.multiselect(
        "Regulatory targets",
        options=list(reg_label_to_id.keys()),
        default=default_reg_labels,
        help="Frameworks your assurance program maps to.",
    )

    workforce_label_to_id = {lab: sid for lab, sid in WORKFORCE_OPTIONS}
    wf_label_list = list(workforce_label_to_id.keys())
    wf_default_idx = 0
    if existing and str(existing.get("workforce_model", "onsite")).strip() == "remote":
        wf_default_idx = 1
    workforce_pick = st.radio(
        "Workforce model",
        wf_label_list,
        index=min(wf_default_idx, len(wf_label_list) - 1),
        horizontal=True,
        help="Remote / hybrid enables the **Access Control** policy in Policy Generator.",
    )
    workforce_id = workforce_label_to_id[workforce_pick]

    sens_ids = [sens_label_to_id[x] for x in sens_labels]
    reg_ids = [reg_label_to_id[x] for x in reg_labels]

    alert_preview, kw_preview = compute_alert_profile(
        business_type, sens_ids, reg_ids
    )

    st.subheader("Effective alert profile (preview)")
    st.json(
        {
            "alert_sensitivity": alert_preview,
            "derived_pii_keywords": kw_preview,
        }
    )

    if st.button("Save client policy", type="primary", key=f"sv_save_policy_{client_id}"):
        out = write_client_policy_file(
            client_id,
            business_type,
            sens_ids,
            reg_ids,
            workforce_model=workforce_id,
        )
        load_events_df.clear()
        st.success(
            f"Saved policy to `{out}`. Ingestion merges this with `settings.yaml` when "
            f"`--data-dir` is `clients/{client_id}/data`."
        )


def _wiz_collect_draft(client_id: str) -> dict[str, object]:
    env_labels = [x[0] for x in SYSTEM_ENVIRONMENT_OPTIONS]
    env_default = env_labels[0]
    return {
        "organization_name": str(
            st.session_state.get(f"wiz_{client_id}_org", "") or ""
        ),
        "industry_vertical": str(
            st.session_state.get(f"wiz_{client_id}_ind", INDUSTRY_VERTICALS[0])
        ),
        "data_type_labels": list(
            st.session_state.get(f"wiz_{client_id}_data", []) or []
        ),
        "compliance_labels": list(
            st.session_state.get(f"wiz_{client_id}_comp", []) or []
        ),
        "system_environment_label": str(
            st.session_state.get(f"wiz_{client_id}_env", env_default)
        ),
    }


def _wiz_hydrate_session(
    client_id: str,
    existing: dict[str, object] | None,
    ws: dict[str, object],
) -> None:
    draft = ws.get("draft") if isinstance(ws.get("draft"), dict) else {}
    dt_label_to_id = {lab: sid for lab, sid in DATA_TYPE_OPTIONS}
    cg_label_to_id = {lab: sid for lab, sid in COMPLIANCE_GOAL_OPTIONS}
    rev_dt = {sid: lab for lab, sid in DATA_TYPE_OPTIONS}
    rev_cg = {sid: lab for lab, sid in COMPLIANCE_GOAL_OPTIONS}

    def _prof_data_labels() -> list[str]:
        out: list[str] = []
        if existing and isinstance(existing.get("data_types_stored"), list):
            for sid in existing["data_types_stored"]:
                if isinstance(sid, str) and sid in rev_dt:
                    out.append(rev_dt[sid])
        return out

    def _prof_comp_labels() -> list[str]:
        out = []
        if existing and isinstance(existing.get("compliance_goals"), list):
            for sid in existing["compliance_goals"]:
                if isinstance(sid, str) and sid in rev_cg:
                    out.append(rev_cg[sid])
        return out

    def _prof_env_label() -> str:
        ev = str((existing or {}).get("system_environment") or "windows_first")
        for lab, eid in SYSTEM_ENVIRONMENT_OPTIONS:
            if eid == ev:
                return lab
        return SYSTEM_ENVIRONMENT_OPTIONS[0][0]

    if f"wiz_{client_id}_org" not in st.session_state:
        st.session_state[f"wiz_{client_id}_org"] = draft.get(
            "organization_name",
            str((existing or {}).get("organization_name", "") or ""),
        )
    if f"wiz_{client_id}_ind" not in st.session_state:
        iv = draft.get("industry_vertical") or (existing or {}).get(
            "industry_vertical", INDUSTRY_VERTICALS[0]
        )
        st.session_state[f"wiz_{client_id}_ind"] = (
            iv if iv in INDUSTRY_VERTICALS else INDUSTRY_VERTICALS[0]
        )
    if f"wiz_{client_id}_data" not in st.session_state:
        dl = draft.get("data_type_labels")
        if isinstance(dl, list) and dl:
            st.session_state[f"wiz_{client_id}_data"] = [
                x for x in dl if x in dt_label_to_id
            ]
        else:
            st.session_state[f"wiz_{client_id}_data"] = _prof_data_labels()
    if f"wiz_{client_id}_comp" not in st.session_state:
        cl = draft.get("compliance_labels")
        if isinstance(cl, list) and cl:
            st.session_state[f"wiz_{client_id}_comp"] = [
                x for x in cl if x in cg_label_to_id
            ]
        else:
            st.session_state[f"wiz_{client_id}_comp"] = _prof_comp_labels()
    if f"wiz_{client_id}_env" not in st.session_state:
        st.session_state[f"wiz_{client_id}_env"] = draft.get(
            "system_environment_label",
            _prof_env_label(),
        )


def _wiz_clear_session_keys(client_id: str) -> None:
    prefs = (
        f"sv_wiz_step_{client_id}",
        f"sv_wiz_preview_ready_{client_id}",
        f"sv_wiz_preview_md_{client_id}",
    )
    for k in list(st.session_state.keys()):
        if k.startswith(f"wiz_{client_id}_") or k in prefs:
            del st.session_state[k]


def _wiz_render_stepper(current_step: int) -> None:
    labels = [
        "Business Profile",
        "Data Mapping",
        "Framework Selection",
        "Policy Generation",
    ]
    st.markdown(
        """
        <style>
        .sv-wiz-step { text-align:center; padding:0.5rem 0.35rem; border-radius:10px;
          font-size:0.8rem; font-weight:600; color:#64748b; }
        .sv-wiz-step.done { background:#ecfdf5; color:#047857; border:1px solid #a7f3d0; }
        .sv-wiz-step.active { background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; }
        .sv-wiz-step.wait { background:#f8fafc; border:1px dashed #e2e8f0; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    c0, c1, c2, c3 = st.columns(4)
    cols = (c0, c1, c2, c3)
    for i, lab in enumerate(labels):
        with cols[i]:
            if current_step > i:
                st.markdown(
                    f'<div class="sv-wiz-step done">✓ {lab}</div>',
                    unsafe_allow_html=True,
                )
            elif current_step == i:
                st.markdown(
                    f'<div class="sv-wiz-step active">{i + 1}. {lab}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="sv-wiz-step wait">{i + 1}. {lab}</div>',
                    unsafe_allow_html=True,
                )


def render_client_onboarding_wizard_tab(client_id: str) -> None:
    """
    Streamlit **Client Onboarding Wizard** — writes ``clients/<id>/client_profile.json``
    and computes an initial **risk profile** (Low / Medium / High) from data types and context.

    Four-step flow with persisted progress in ``onboarding_wizard_state.json`` until save completes.
    """
    st.caption(
        "Capture organization context for documentation and planning. This file is separate "
        "from **Onboarding** (`client_policy.json`) which tunes SIEM analysis."
    )
    ensure_client_layout(client_id)

    banner_key = f"wiz_saved_banner_{client_id}"
    if banner_key in st.session_state:
        payload = st.session_state.pop(banner_key)
        doc = payload["doc"]
        path = payload["path"]
        rp = doc["risk_profile"]
        badge_color = (
            "#b91c1c"
            if rp == "High"
            else ("#c2410c" if rp == "Medium" else "#166534")
        )
        st.success(f"Saved profile to `{path}`")
        st.markdown(
            f'<p style="font-size:1.1rem;font-weight:700;color:{badge_color};">'
            f"Initial risk profile: {rp}</p>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**Rationale:** {doc['risk_rationale']}")
        st.info(
            "Wizard draft cleared — your progress file was removed because "
            "`client_profile.json` is now saved (refresh-safe)."
        )

    existing = load_client_profile(client_id)
    ws = load_wizard_state(client_id)

    step_key = f"sv_wiz_step_{client_id}"
    if step_key not in st.session_state:
        st.session_state[step_key] = int(ws.get("step", 0))

    _wiz_hydrate_session(client_id, existing, ws)

    dt_label_to_id = {lab: sid for lab, sid in DATA_TYPE_OPTIONS}
    cg_label_to_id = {lab: sid for lab, sid in COMPLIANCE_GOAL_OPTIONS}
    env_label_to_id = {lab: sid for lab, sid in SYSTEM_ENVIRONMENT_OPTIONS}

    step = int(st.session_state[step_key])
    step = max(0, min(3, step))
    st.session_state[step_key] = step

    _wiz_render_stepper(step)

    # --- Step bodies ---
    if step == 0:
        st.subheader("Business Profile")
        st.text_input(
            "Organization name",
            max_chars=240,
            placeholder="Legal or operating name",
            key=f"wiz_{client_id}_org",
        )
        st.selectbox(
            "Industry vertical",
            INDUSTRY_VERTICALS,
            key=f"wiz_{client_id}_ind",
        )
        step_ok = bool(str(st.session_state.get(f"wiz_{client_id}_org", "")).strip())

    elif step == 1:
        st.subheader("Data Mapping")
        st.multiselect(
            "Data types stored",
            options=list(dt_label_to_id.keys()),
            key=f"wiz_{client_id}_data",
            help="Selections strongly influence the computed risk profile (e.g. PHI / PCI → High).",
        )
        step_ok = len(st.session_state.get(f"wiz_{client_id}_data", []) or []) >= 1

    elif step == 2:
        st.subheader("Framework Selection")
        st.multiselect(
            "Compliance goals",
            options=list(cg_label_to_id.keys()),
            key=f"wiz_{client_id}_comp",
        )
        step_ok = len(st.session_state.get(f"wiz_{client_id}_comp", []) or []) >= 1

    else:
        st.subheader("Policy Generation")
        env_options = list(env_label_to_id.keys())
        st.selectbox(
            "System environment",
            env_options,
            key=f"wiz_{client_id}_env",
        )

        preview_ready = f"sv_wiz_preview_ready_{client_id}"
        preview_md = f"sv_wiz_preview_md_{client_id}"
        draft_dict = _wiz_collect_draft(client_id)
        dt_ids = [dt_label_to_id[x] for x in draft_dict["data_type_labels"] if x in dt_label_to_id]
        cg_ids = [cg_label_to_id[x] for x in draft_dict["compliance_labels"] if x in cg_label_to_id]
        env_id = env_label_to_id.get(
            str(draft_dict.get("system_environment_label") or env_options[0]),
            "windows_first",
        )
        profile_doc = build_client_profile_document(
            str(draft_dict["organization_name"]).strip()
            or "Organization",
            str(draft_dict["industry_vertical"]),
            dt_ids,
            cg_ids,
            env_id,
        )

        if ws.get("mapping_animation_seen") and preview_ready not in st.session_state:
            st.session_state[preview_ready] = True
            st.session_state[preview_md] = generate_data_handling_policy_engine(profile_doc)

        if preview_ready not in st.session_state:
            with st.spinner("Mapping Frameworks to System Controls..."):
                time.sleep(2.2)
            st.session_state[preview_md] = generate_data_handling_policy_engine(profile_doc)
            st.session_state[preview_ready] = True
            save_wizard_state(
                client_id,
                step=3,
                draft=_wiz_collect_draft(client_id),
                mapping_animation_seen=True,
            )
            st.rerun()

        st.success(
            "Framework mapping complete — here is a preview of your **Data Handling Policy**."
        )
        with st.expander("Data Handling Policy (preview)", expanded=True):
            st.markdown(st.session_state.get(preview_md, ""))

        step_ok = True

    # --- Navigation ---
    st.divider()
    n1, n2, n3 = st.columns([1, 1, 2])
    with n1:
        if step > 0 and st.button("← Back", key=f"wiz_back_{client_id}"):
            st.session_state[step_key] = step - 1
            save_wizard_state(
                client_id,
                step=st.session_state[step_key],
                draft=_wiz_collect_draft(client_id),
            )
            st.rerun()
    with n2:
        if step < 3:
            if st.button(
                "Next →",
                type="primary",
                disabled=not step_ok,
                key=f"wiz_next_{client_id}",
            ):
                st.session_state[step_key] = step + 1
                save_wizard_state(
                    client_id,
                    step=st.session_state[step_key],
                    draft=_wiz_collect_draft(client_id),
                )
                st.rerun()

    if step == 3:
        st.divider()
        if st.button(
            "Save client profile",
            type="primary",
            key=f"wiz_save_profile_{client_id}",
        ):
            d = _wiz_collect_draft(client_id)
            dt_ids_s = [dt_label_to_id[x] for x in d["data_type_labels"] if x in dt_label_to_id]
            cg_ids_s = [cg_label_to_id[x] for x in d["compliance_labels"] if x in cg_label_to_id]
            env_id_s = env_label_to_id.get(str(d.get("system_environment_label")), "windows_first")
            path = write_client_profile_file(
                client_id,
                str(d["organization_name"]).strip(),
                str(d["industry_vertical"]),
                dt_ids_s,
                cg_ids_s,
                env_id_s,
            )
            doc = build_client_profile_document(
                str(d["organization_name"]).strip(),
                str(d["industry_vertical"]),
                dt_ids_s,
                cg_ids_s,
                env_id_s,
            )
            clear_wizard_state(client_id)
            _wiz_clear_session_keys(client_id)
            st.session_state[banner_key] = {"path": str(path), "doc": doc}
            st.session_state[step_key] = 0
            st.rerun()


def render_policy_generator_tab(client_id: str, report_org: str) -> None:
    """Policy Generation Engine: Markdown + PDF from ``client_profile.json``."""
    st.caption(
        "Templates: **Data Handling Policy**, **Access Control Policy**, **Incident Response Plan**. "
        "Variables come from **Client Onboarding Wizard** (`client_profile.json`). Conditional "
        "sections (e.g. personal data sanitization for **PII**) and **Compliance Reference** tables "
        "(SOC 2 TSC when applicable, else ISO 27001 Annex A) are injected automatically."
    )
    profile = load_client_profile(client_id)
    if not profile:
        st.warning(
            "Save a **client profile** first (**Client Onboarding Wizard**) — organization name, "
            "industry, data types, and compliance goals drive generation."
        )
        return

    policies = generate_policies_from_client_profile(profile)
    if not policies:
        st.error("Policy engine returned no documents — check client profile data.")
        return

    org_out = (profile.get("organization_name") or report_org or "").strip() or "Organization"

    st.subheader("Included in this package")
    for name in policies:
        st.markdown(f"- **{name}**")

    _dd, _ = ensure_client_layout(client_id)
    _bridge_df = load_events_df(str(_dd))
    render_policy_evidence_bridge(policies, _bridge_df, client_id=client_id)

    with st.expander("Preview (Markdown)", expanded=False):
        st.markdown(policies_engine_markdown_bundle(policies, org_out))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_org = re.sub(r"[^\w\-.]+", "_", org_out)[:48]
    try:
        pdf_bytes = build_policies_pdf_bytes(
            policies,
            organization=org_out,
        )
        st.download_button(
            label="Download policies as PDF",
            data=pdf_bytes,
            file_name=f"{safe_org}_Policy_Package_{stamp}.pdf",
            mime="application/pdf",
            type="primary",
            key=f"sv_policy_pdf_{client_id}",
        )
    except ImportError as exc:
        st.warning(str(exc))

    md_bundle = policies_engine_markdown_bundle(policies, org_out)
    st.download_button(
        label="Download combined Markdown",
        data=md_bundle.encode("utf-8"),
        file_name=f"{safe_org}_Policy_Package_{stamp}.md",
        mime="text/markdown",
        key=f"sv_policy_md_{client_id}",
    )


def render_configuration_tab(settings_path: Path) -> None:
    st.subheader("Analysis configuration (settings.yaml)")
    st.caption(
        "Define **PII keywords** (matched in `File_Path`, case-insensitive) in addition "
        "to the `PII_Detected` column, and which path segments count as **public/exposure** "
        "vs **secure** (secure suppresses the public+PII HIGH rule)."
    )
    cur = load_settings(settings_path if settings_path.is_file() else None)
    with st.form("sv_settings_form"):
        pii_ta = st.text_area(
            "PII keywords (one per line)",
            value="\n".join(cur.pii_keywords),
            height=120,
            help="Examples: Account Number, SSN, Tax ID. Matched as substrings in File_Path.",
        )
        pub_ta = st.text_area(
            "Public / exposure folder markers (one per line)",
            value="\n".join(cur.public_path_segments),
            height=100,
            help="If the path contains any of these (case-insensitive), it counts as exposure.",
        )
        sec_ta = st.text_area(
            "Secure folder markers (one per line)",
            value="\n".join(cur.secure_path_segments),
            height=100,
            help="If the path contains any of these, the public+PII HIGH rule is suppressed.",
        )
        save = st.form_submit_button("Save settings.yaml", type="primary")
    if save:
        new_cfg = settings_from_form_lines(pii_ta, pub_ta, sec_ta)
        save_settings(settings_path, new_cfg)
        st.success(f"Saved: {settings_path}")
        st.info("Re-run ingestion or refresh CSVs for new interpretations to apply.")


def render_dashboard_core(
    df: pd.DataFrame,
    data_dir: Path,
    report_org: str,
    *,
    compact: bool = False,
    client_risk_profile: str | None = None,
) -> None:
    score, n_res, n_unres = _compliance_score(df)

    if not compact:
        m1, m2, m3 = st.columns(3)
        with m1:
            if score is None:
                st.metric(
                    "Compliance health score",
                    "—",
                    help="Resolved events ÷ all events (requires stored events).",
                )
                st.markdown(
                    f'<p style="color:{COLOR_NEUTRAL};font-weight:600;">No events recorded yet.</p>',
                    unsafe_allow_html=True,
                )
            else:
                color_note = (
                    COLOR_GOOD_FG
                    if score >= 80
                    else (COLOR_HIGH_FG if score >= 50 else COLOR_CRITICAL_FG)
                )
                st.metric(
                    "Compliance health score",
                    f"{score:.0f}%",
                    delta=f"{n_res} resolved / {n_res + n_unres} total",
                    delta_color="normal",
                    help="Share of security events marked resolved in the database.",
                )
                st.markdown(
                    f'<p style="color:{color_note};font-weight:700;font-size:1.1rem;">'
                    f"Unresolved: {n_unres}</p>",
                    unsafe_allow_html=True,
                )
        with m2:
            crit_n = len(df[df["risk_level"] == "Critical"]) if len(df) else 0
            st.metric("Critical findings (all time)", str(crit_n))
            equiv = _open_critical_equivalent_count(df, client_risk_profile)
            if (client_risk_profile or "").strip() == "High":
                st.caption(
                    f"Open **critical-equivalent** (profile-weighted): **{equiv}** "
                    "(includes access-review **High** when inherent risk is High)."
                )
            st.markdown(
                f'<p style="color:{COLOR_CRITICAL_FG};font-weight:600;">Red = immediate leadership attention</p>',
                unsafe_allow_html=True,
            )
        with m3:
            high_n = len(df[df["risk_level"] == "High"]) if len(df) else 0
            st.metric("High findings (all time)", str(high_n))
            st.markdown(
                f'<p style="color:{COLOR_HIGH_FG};font-weight:600;">Yellow = priority remediation</p>',
                unsafe_allow_html=True,
            )

        st.divider()
        st.subheader("Critical alerts")
        st.caption(
            "Most urgent interpreted events (Critical and High), with plain-English remediation."
        )
    else:
        st.markdown("###### Urgent queue & response")
        st.caption(
            "Critical and High findings — acknowledgement and resolution roll up to audit exports."
        )

    if df.empty:
        st.info(
            "No events in the database. Run **ingest_engine.py** against your inbox; "
            "events are written to **sentinelview_events.sqlite** in the event data folder."
        )
    else:
        urgent = df[df["risk_level"].isin(["Critical", "High"])].copy()
        urgent["_prio"] = urgent["risk_level"].map({"Critical": 0, "High": 1}).fillna(9)
        urgent = urgent.sort_values(by=["_prio", "ts"], ascending=[True, False]).drop(
            columns=["_prio"]
        )
        if "acknowledged" in urgent.columns:
            urgent["acknowledged"] = urgent["acknowledged"].fillna(0).astype(int)
        else:
            urgent["acknowledged"] = 0
        if urgent.empty:
            st.success("No Critical or High alerts — outstanding posture on urgent items.")
        else:
            render_actionable_alert_feed(
                df,
                data_dir,
                client_risk_profile,
                key_ns="overview",
                load_events_df_clear=load_events_df.clear,
            )

    if compact:
        return

    st.divider()
    st.subheader("Privacy heatmap")
    st.caption(
        "Where privacy_scan events cluster by volume / path (more flags = hotter). "
        "Public-style exposure is defined in **Configuration** / settings.yaml."
    )

    priv = df[df["source_log"] == "privacy_scan"].copy()
    if priv.empty:
        st.warning(
            "No privacy_scan events yet — the heatmap will populate when PII-related "
            "findings are ingested."
        )
    else:
        priv["file_path"] = priv["context_json"].map(_file_path_from_context)
        priv["system_volume"] = priv["file_path"].map(_privacy_system_volume)
        counts = (
            priv.groupby("system_volume", as_index=False)
            .size()
            .rename(columns={"size": "flags"})
            .sort_values("flags", ascending=False)
        )
        max_f = max(int(counts["flags"].max()), 1)
        bar_h = 26
        chart_h = min(480, bar_h * max(6, len(counts)))
        chart = (
            alt.Chart(counts)
            .mark_bar(height=bar_h)
            .encode(
                x=alt.X(
                    "flags:Q",
                    title="Number of privacy flags",
                    axis=alt.Axis(grid=True),
                ),
                y=alt.Y("system_volume:N", sort="-x", title="System / path volume"),
                color=alt.Color(
                    "flags:Q",
                    title="Heat",
                    scale=alt.Scale(
                        domain=[0, max_f],
                        range=["#22c55e", "#facc15", "#dc2626"],
                    ),
                    legend=alt.Legend(
                        orient="bottom",
                        title="Green = fewer flags · Red = more flags",
                    ),
                ),
                tooltip=["system_volume", "flags"],
            )
            .properties(height=chart_h)
        )
        st.altair_chart(chart, use_container_width=True)

    st.divider()
    st.subheader("Compliance Summary Report (audit evidence)")
    st.caption(
        "Export a full register of security events with detection dates, policy "
        "mapping (NIST AI RMF, NIST SP 800-53, CDD/KYC-aligned controls), and remediation "
        "disposition for regulators or external auditors."
    )
    gen_ts = datetime.now(timezone.utc)
    stamp = gen_ts.strftime("%Y%m%d_%H%M%S")
    safe_org = re.sub(r"[^\w\-.]+", "_", report_org.strip() or "Organization")[:48]
    if df.empty:
        st.info(
            "No events to export yet. After **ingest_engine** records findings, return "
            "here to generate Markdown or PDF evidence packs."
        )
    else:
        df_export = df.sort_values("ts", ascending=True)
        records = df_export.to_dict("records")
        md_text = build_compliance_summary_markdown(
            records,
            generated_utc=gen_ts,
            organization=report_org.strip() or "Organization",
        )
        c_md, c_pdf = st.columns(2)
        with c_md:
            st.download_button(
                label="Download Compliance Summary (Markdown)",
                data=md_text.encode("utf-8"),
                file_name=f"SentinelView_Compliance_Summary_{safe_org}_{stamp}.md",
                mime="text/markdown",
                type="primary",
                use_container_width=True,
            )
        with c_pdf:
            try:
                pdf_bytes = build_compliance_summary_pdf(
                    records,
                    generated_utc=gen_ts,
                    organization=report_org.strip() or "Organization",
                )
                st.download_button(
                    label="Download Compliance Summary (PDF)",
                    data=pdf_bytes,
                    file_name=f"SentinelView_Compliance_Summary_{safe_org}_{stamp}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except ImportError as exc:
                st.warning(str(exc))


def render_global_risk_admin() -> None:
    """Admin aggregate: critical/high exposure across every ``clients/<id>/data`` store."""
    root = Path.cwd().resolve()
    summary, crit = load_global_risk_data(str(root))
    st.caption(
        "Roll-up across **all** folders under `clients/*/data`. "
        "Ingest each client with `--data-dir clients/<id>/data` and watch `clients/<id>/logs`."
    )
    clients_n = len(list_registered_clients())
    if clients_n == 0:
        st.info(
            "No workspaces yet. Create `clients/<client_name>/data` and "
            "`clients/<client_name>/logs` (see **Connection** when a client is selected)."
        )
        return

    tot_e = int(summary["Events"].sum()) if len(summary) and "Events" in summary.columns else 0
    tot_crit = int(summary["Critical (open)"].sum()) if len(summary) else 0
    tot_high = int(summary["High (open)"].sum()) if len(summary) else 0
    clients_with_crit = int((summary["Critical (open)"] > 0).sum()) if len(summary) else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Clients onboarded", str(clients_n))
    with m2:
        st.metric("Open Critical (all SMBs)", str(tot_crit))
    with m3:
        st.metric("Open High (all SMBs)", str(tot_high))
    with m4:
        st.metric("SMBs with open Critical", str(clients_with_crit))

    st.divider()
    st.subheader("Per-client summary")
    if summary.empty:
        st.warning("No event data in any client store.")
    else:
        st.dataframe(summary, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Open Critical alerts (all clients)")
    if crit.empty:
        st.success("No open Critical findings across managed clients.")
    else:
        show_cols = [
            c
            for c in (
                "client_id",
                "ts",
                "risk_level",
                "summary",
                "source_log",
                "detail",
                "event_id",
            )
            if c in crit.columns
        ]
        st.dataframe(
            crit[show_cols],
            use_container_width=True,
            hide_index=True,
            height=min(520, 80 + 36 * len(crit)),
        )

    st.divider()
    st.caption(f"Total events indexed: **{tot_e}** · Workspace root: `{root}`")


def main() -> None:
    st.set_page_config(
        page_title="SentinelView — GRC",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        "<style>.block-container { padding-top: 1rem; }</style>",
        unsafe_allow_html=True,
    )
    inject_trust_center_theme()

    default_txt = str(_suggested_event_data_dir().resolve())
    settings_default = str((Path.cwd() / "settings.yaml").resolve())
    clients_root().mkdir(parents=True, exist_ok=True)

    client_options = [GLOBAL_CLIENT_LABEL] + list_registered_clients()
    client_default_index = 1 if len(client_options) > 1 else 0

    # (section title, [(sidebar label, internal session key), ...])
    _SIDEBAR_NAV: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
        (
            "Operations",
            (
                ("Security Overview", "Trust Center"),
                ("Issues & Fixes", "Control Monitoring"),
                ("Activity Log", "Evidence Library"),
            ),
        ),
        (
            "Compliance",
            (
                ("Compliance Setup", "Client Onboarding Wizard"),
                ("Policies", "Policy Generator"),
                ("Reports", "Overview & analytics"),
            ),
        ),
        (
            "Admin",
            (
                ("Clients", "Global Risk (Admin)"),
                ("Settings", "Configuration"),
            ),
        ),
    )

    with st.sidebar:
        st.markdown(
            '<p class="sv-brand">SentinelView</p>'
            '<p class="sv-brand-sub">Governance · Risk · Compliance</p>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p class="sv-nav-group-label" style="margin-top:0;">Client</p>',
            unsafe_allow_html=True,
        )
        client_pick = st.selectbox(
            "Active client workspace",
            client_options,
            index=min(client_default_index, len(client_options) - 1),
            key="sv_client_sel",
            help="Each tenant has an isolated workspace (event store and ingest logs). "
            "Use Global for cross-tenant admin views.",
            label_visibility="collapsed",
        )
        _client_data_dir: Path | None = None
        _client_logs_dir: Path | None = None
        if client_pick != GLOBAL_CLIENT_LABEL:
            _client_data_dir, _client_logs_dir = ensure_client_layout(client_pick)
            st.markdown(
                '<div class="sv-status-badge"><span class="sv-status-dot"></span>'
                "Active Connection</div>",
                unsafe_allow_html=True,
            )
        else:
            st.caption(
                "Choose a named client for tenant dashboards, or open **Clients** under Admin."
            )

        if "sv_primary_nav" not in st.session_state:
            st.session_state.sv_primary_nav = "Trust Center"

        for _section_title, _items in _SIDEBAR_NAV:
            st.markdown(
                f'<p class="sv-nav-group-label">{html.escape(_section_title)}</p>',
                unsafe_allow_html=True,
            )
            for _display, _internal in _items:
                _ac, _tx = st.columns([0.055, 0.945])
                with _ac:
                    if st.session_state.sv_primary_nav == _internal:
                        st.markdown(
                            '<div class="sv-nav-accent-bar"></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            '<div class="sv-nav-accent-spacer"></div>',
                            unsafe_allow_html=True,
                        )
                with _tx:
                    if st.button(
                        _display,
                        key=f"svbtn_nav_{_internal}",
                        use_container_width=True,
                        type="tertiary",
                    ):
                        st.session_state.sv_primary_nav = _internal
                        st.rerun()

        view = st.session_state.sv_primary_nav

        st.divider()
        st.markdown('<p class="sv-nav-group-label">Connection</p>', unsafe_allow_html=True)
        custom_override = st.text_input(
            "Custom event data folder (optional override)",
            value="",
            key="sv_custom_data_override",
            placeholder="Leave blank — uses selected client's data/",
            help="Overrides the active data store when non-empty (advanced deployments).",
        )
        if client_pick != GLOBAL_CLIENT_LABEL:
            _resolved = _client_data_dir or Path(default_txt).resolve()
        else:
            _resolved = Path(default_txt).resolve()
        if custom_override.strip():
            data_dir = Path(custom_override.strip()).expanduser().resolve()
        else:
            data_dir = _resolved
        with st.expander("Path details (admin)", expanded=False):
            if client_pick != GLOBAL_CLIENT_LABEL and _client_logs_dir is not None:
                st.caption(
                    f"**Event store:** `{data_dir}`\n\n**Logs:** `{_client_logs_dir}`"
                )
            else:
                st.caption(f"**Event store:** `{data_dir}`")
        report_org = st.text_input(
            "Organization (reports)",
            value=client_pick if client_pick != GLOBAL_CLIENT_LABEL else "Organization",
            help="Printed on audit exports.",
        )
        settings_str = st.text_input(
            "settings.yaml path",
            value=settings_default,
            help="Align with ingest_engine --settings when used.",
        )
        settings_path = Path(
            settings_str.strip() or settings_default
        ).expanduser().resolve()
        if st.button("Refresh data", type="secondary"):
            load_events_df.clear()
            load_global_risk_data.clear()
            st.rerun()

        if client_pick != GLOBAL_CLIENT_LABEL:
            _soc_prof = load_client_profile(client_pick)
            _cg = _soc_prof.get("compliance_goals") if _soc_prof else None
            if _soc_prof and isinstance(_cg, list) and "SOC2" in _cg:
                st.markdown(
                    '<p class="sv-nav-group-label">SOC 2 readiness</p>',
                    unsafe_allow_html=True,
                )
                _sdf = load_events_df(str(data_dir))
                _sc, _, _ = _compliance_score(_sdf)
                _s2, _ = _framework_readiness(_sdf, _sc)
                st.progress(min(1.0, max(0.0, _s2 / 100.0)))
                st.caption(
                    f"Illustrative index from disposition: **{_s2:.0f}%** "
                    "(same basis as Security Overview readiness bars)."
                )

        render_sidebar_managed_footer()

    profile_doc: dict[str, object] | None = (
        load_client_profile(client_pick)
        if client_pick != GLOBAL_CLIENT_LABEL
        else None
    )
    if client_pick != GLOBAL_CLIENT_LABEL and view not in (
        "Client Onboarding Wizard",
        "Onboarding",
    ):
        render_audit_ready_hero(key_prefix="sv_hero")

    client_risk: str | None = None
    if profile_doc:
        rp_raw = str(profile_doc.get("risk_profile") or "").strip()
        client_risk = rp_raw if rp_raw else None
    display_org_top = (report_org or "").strip() or (
        client_pick if client_pick != GLOBAL_CLIENT_LABEL else "Organization"
    )
    if profile_doc and str(profile_doc.get("organization_name") or "").strip():
        display_org_top = str(profile_doc.get("organization_name")).strip()
    hipaa_evidence = bool(
        profile_doc
        and isinstance(profile_doc.get("compliance_goals"), list)
        and "HIPAA" in profile_doc["compliance_goals"]
    )

    titles = {
        "Global Risk (Admin)": "Clients — workspace overview",
        "Trust Center": "Security & Compliance Overview",
        "Control Monitoring": "Issues & Fixes",
        "Evidence Library": "Activity Log",
        "Overview & analytics": "Reports",
        "Client Onboarding Wizard": "Compliance Setup",
        "Onboarding": "Security questionnaire",
        "Policy Generator": "Policies",
        "Configuration": "Settings",
    }

    if view == "Global Risk (Admin)":
        st.title(titles[view])
        render_global_risk_admin()
    elif view == "Configuration":
        st.title(titles[view])
        render_configuration_tab(settings_path)
    elif view == "Client Onboarding Wizard":
        if client_pick == GLOBAL_CLIENT_LABEL:
            st.title(titles[view])
            st.warning(
                "Select a **specific client** in the sidebar to run the onboarding wizard "
                "for that tenant."
            )
        else:
            df_head = load_events_df(str(data_dir))
            render_profile_aware_heading(
                display_org=display_org_top,
                profile=profile_doc,
                df=df_head,
                client_risk_profile=client_risk,
            )
            st.title(titles[view])
            st.caption(f"Workspace: `{client_pick}`")
            render_client_onboarding_wizard_tab(client_pick)
    elif view == "Onboarding":
        if client_pick == GLOBAL_CLIENT_LABEL:
            st.title(titles[view])
            st.warning(
                "Select a **specific client** in the sidebar to open the onboarding form "
                "for that tenant."
            )
        else:
            df_head = load_events_df(str(data_dir))
            render_profile_aware_heading(
                display_org=display_org_top,
                profile=profile_doc,
                df=df_head,
                client_risk_profile=client_risk,
            )
            st.title(titles[view])
            st.caption(f"Workspace: `{client_pick}`")
            render_onboarding_tab(client_pick)
    elif view == "Policy Generator":
        if client_pick == GLOBAL_CLIENT_LABEL:
            st.title(titles[view])
            st.warning(
                "Select a **specific client** in the sidebar to generate policies for that "
                "tenant (uses **Compliance Setup** and questionnaire data)."
            )
        else:
            df_head = load_events_df(str(data_dir))
            render_profile_aware_heading(
                display_org=display_org_top,
                profile=profile_doc,
                df=df_head,
                client_risk_profile=client_risk,
            )
            st.title(titles[view])
            st.caption(f"Workspace: `{client_pick}`")
            render_policy_generator_tab(client_pick, report_org)
    elif client_pick == GLOBAL_CLIENT_LABEL:
        if custom_override.strip():
            data_dir = Path(custom_override.strip()).expanduser().resolve()
            st.caption("Custom data folder override is active. Path details are under **Connection → Path details (admin)** in the sidebar.")
            df = load_events_df(str(data_dir))
            render_global_override_heading(df, report_org)
            if view != "Trust Center":
                st.title(titles[view])
            if view == "Trust Center":
                render_trust_center_tab(
                    df,
                    data_dir,
                    report_org,
                    client_risk_profile=None,
                    client_id=None,
                )
            elif view == "Control Monitoring":
                render_control_monitoring_tab(df, data_dir, client_risk_profile=None)
            elif view == "Evidence Library":
                render_evidence_library_tab(df, data_dir, report_org, hipaa_labels=False)
            elif view == "Overview & analytics":
                render_dashboard_core(
                    df,
                    data_dir,
                    report_org,
                    compact=False,
                    client_risk_profile=None,
                )
            else:
                st.warning(
                    "Choose a view in the sidebar under **Operations**, **Compliance**, or **Admin**."
                )
        else:
            st.title(titles[view])
            st.warning(
                "Select a **client** in the sidebar (not Global) to load that tenant's "
                "health score, risks, and evidence — each workspace uses `clients/<name>/data` "
                "and `clients/<name>/logs`."
            )
            st.info(
                "Use **Clients** under Admin to see critical alerts across all managed workspaces "
                "at once. You may also set **Custom event data folder** above for a legacy "
                "single-directory deployment."
            )
    else:
        df = load_events_df(str(data_dir))
        render_profile_aware_heading(
            display_org=display_org_top,
            profile=profile_doc,
            df=df,
            client_risk_profile=client_risk,
        )
        if view != "Trust Center":
            st.title(titles[view])
            st.caption(f"Workspace: `{client_pick}`")
        if view == "Trust Center":
            render_trust_center_tab(
                df,
                data_dir,
                report_org,
                client_risk_profile=client_risk,
                client_id=client_pick,
            )
        elif view == "Control Monitoring":
            render_control_monitoring_tab(df, data_dir, client_risk_profile=client_risk)
        elif view == "Evidence Library":
            render_evidence_library_tab(
                df, data_dir, report_org, hipaa_labels=hipaa_evidence
            )
        elif view == "Overview & analytics":
            render_dashboard_core(
                df,
                data_dir,
                report_org,
                compact=False,
                client_risk_profile=client_risk,
            )


main()
