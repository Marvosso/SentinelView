"""
Security & Compliance Overview — SMB-friendly Trust Center replacement UI.

Uses Tailwind-inspired utility class names (see SCO_PAGE_CSS). Streamlit does not execute
arbitrary script tags in markdown, so Tailwind CDN is not injected; styles mirror the scale.
"""

from __future__ import annotations

import html as html_module
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pandas as pd
import streamlit as st

from trust_center_ui import (
    count_evidence_items_today,
    count_open_remediations,
    critical_open_in_last_hour,
    days_since_framework_update,
    render_actionable_alert_feed,
)

SCO_PAGE_CSS = """
.sv-sco-page {
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
  color: #e2e8f0;
}
.sv-sco-constrain {
  max-width: 1200px;
  margin-left: auto;
  margin-right: auto;
}
.sv-sco-h1 {
  font-size: 1.75rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  color: #f8fafc;
  margin: 0 0 0.35rem 0;
  line-height: 1.2;
}
.sv-sco-sub {
  font-size: 1rem;
  color: #94a3b8;
  font-weight: 500;
  margin: 0 0 0.5rem 0;
  line-height: 1.45;
  max-width: 42rem;
}
.sv-sco-workspace {
  font-size: 0.85rem;
  color: #94a3b8;
  font-weight: 600;
  margin-bottom: 1.25rem;
}
.sv-sco-card {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 1rem;
  padding: 1.25rem 1.35rem;
  margin-bottom: 1rem;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.35);
}
.sv-sco-card--accent {
  border: 1px solid #1f2937;
  border-left: 3px solid #4f46e5;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.35);
}
.sv-sco-status-row {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  gap: 1rem;
  justify-content: space-between;
}
.sv-sco-live-dot {
  width: 12px;
  height: 12px;
  border-radius: 999px;
  flex-shrink: 0;
  margin-top: 0.35rem;
}
.sv-sco-live-dot--ok {
  background: #22c55e;
  box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.2);
}
.sv-sco-live-dot--warn {
  background: #f59e0b;
}
.sv-sco-status-title {
  font-size: 1.15rem;
  font-weight: 800;
  color: #f8fafc;
  margin: 0 0 0.35rem 0;
}
.sv-sco-status-body {
  font-size: 0.92rem;
  color: #cbd5e1;
  line-height: 1.5;
  margin: 0;
  max-width: 36rem;
}
.sv-sco-muted-line {
  font-size: 0.8rem;
  color: #64748b;
  margin-top: 0.75rem;
  line-height: 1.45;
}
.sv-sco-risk-pill {
  display: inline-block;
  padding: 0.35rem 0.75rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
  background: rgba(79, 70, 229, 0.12);
  color: #a5b4fc;
  border: 1px solid rgba(79, 70, 229, 0.35);
  white-space: nowrap;
}
.sv-sco-kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 1.25rem;
  max-width: 1200px;
  margin-left: auto;
  margin-right: auto;
}
.sv-sco-kpi-card {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 1rem;
  padding: 1rem 1.1rem;
  min-height: 7.5rem;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.35);
}
.sv-sco-kpi-card--warn {
  border-color: rgba(251, 191, 36, 0.35);
  box-shadow: 0 0 0 1px rgba(251, 191, 36, 0.08);
}
.sv-sco-kpi-icon { font-size: 1.35rem; margin-bottom: 0.35rem; }
.sv-sco-kpi-label {
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #94a3b8;
  margin-bottom: 0.35rem;
}
.sv-sco-kpi-value {
  font-size: 1.85rem;
  font-weight: 800;
  color: #f8fafc;
  line-height: 1.1;
  margin-bottom: 0.35rem;
}
.sv-sco-kpi-help {
  font-size: 0.8rem;
  color: #64748b;
  line-height: 1.35;
}
.sv-sco-action-card {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 1rem;
  padding: 1.25rem 1.35rem;
  margin-bottom: 1.25rem;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.35);
}
.sv-sco-action-title {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #94a3b8;
  margin-bottom: 0.45rem;
}
.sv-sco-action-body {
  font-size: 1rem;
  font-weight: 600;
  color: #e2e8f0;
  margin: 0 0 0.75rem 0;
  line-height: 1.45;
  max-width: 40rem;
}
.sv-sco-section-title {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #64748b;
  margin: 0 0 0.65rem 0;
}
.sv-sco-rec-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem 1rem;
  padding: 0.85rem 0;
  border-bottom: 1px solid rgba(51, 65, 85, 0.45);
}
.sv-sco-rec-row:last-child { border-bottom: none; }
.sv-sco-rec-icon { font-size: 1.25rem; width: 2rem; text-align: center; flex-shrink: 0; }
.sv-sco-rec-text { flex: 1; min-width: 200px; font-size: 0.9rem; color: #cbd5e1; line-height: 1.4; }
.sv-sco-pill {
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.25rem 0.55rem;
  border-radius: 999px;
  border: 1px solid rgba(71, 85, 105, 0.6);
  color: #94a3b8;
  background: rgba(30, 41, 59, 0.6);
  white-space: nowrap;
}
.sv-sco-pill--ready { border-color: rgba(34, 197, 94, 0.45); color: #86efac; background: rgba(22, 101, 52, 0.2); }
.sv-sco-pill--rec { border-color: rgba(79, 70, 229, 0.45); color: #a5b4fc; background: rgba(49, 46, 129, 0.35); }
.sv-sco-readiness-card {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 1rem;
  padding: 1.1rem 1.25rem;
  margin-bottom: 0.35rem;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.35);
}
.sv-sco-calm-notice {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 1rem;
  padding: 1rem 1.25rem;
  margin: 0.35rem 0 1rem 0;
  color: #cbd5e1;
  font-size: 0.92rem;
  line-height: 1.55;
}
.sv-sco-calm-notice__title {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #64748b;
  margin-bottom: 0.35rem;
}
.sv-sco-calm-notice--settled {
  border-left: 3px solid #22c55e;
}
.sv-sco-readiness-line {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: baseline;
  gap: 0.5rem;
}
.sv-sco-readiness-label { font-size: 0.95rem; font-weight: 700; color: #f1f5f9; }
.sv-sco-readiness-tier { font-size: 0.8rem; color: #94a3b8; font-weight: 600; }
.sv-sco-readiness-pct { font-size: 0.85rem; font-weight: 800; color: #a5b4fc; }
[data-testid="stMain"] [data-testid="stProgress"] [data-baseweb="progress-bar"] > div > div,
[data-testid="stMain"] [data-testid="stProgressBar"] [data-baseweb="progress-bar"] > div > div {
  background-color: rgba(51, 65, 85, 0.65) !important;
}
[data-testid="stMain"] [data-testid="stProgress"] [data-baseweb="progress-bar"] > div > div > div,
[data-testid="stMain"] [data-testid="stProgressBar"] [data-baseweb="progress-bar"] > div > div > div {
  background: #4f46e5 !important;
}
@media (max-width: 768px) {
  .sv-sco-h1 { font-size: clamp(1.2rem, 5.5vw, 1.55rem); }
  .sv-sco-sub { font-size: 0.95rem; }
  .sv-sco-status-row {
    flex-direction: column;
    align-items: stretch;
    gap: 1rem;
  }
  .sv-sco-status-row > div:last-child {
    text-align: left !important;
  }
  .sv-sco-status-row .sv-sco-muted-line[style*="margin-left:auto"] {
    margin-left: 0 !important;
    max-width: none !important;
  }
  .sv-sco-kpi-grid { grid-template-columns: 1fr; }
}
"""


def inject_sco_page_css_once() -> None:
    if st.session_state.get("_sv_sco_css_injected"):
        return
    st.session_state["_sv_sco_css_injected"] = True
    st.markdown(f"<style>{SCO_PAGE_CSS}</style>", unsafe_allow_html=True)


def _row_resolved(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def critical_open_in_last_24h(df: pd.DataFrame) -> bool:
    if df.empty or "risk_level" not in df.columns or "ts" not in df.columns:
        return False
    d = df.copy()
    d["_open"] = ~d["resolved"].map(_row_resolved) if "resolved" in d.columns else True
    crit = d[(d["risk_level"] == "Critical") & (d["_open"])]
    if crit.empty:
        return False
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    ts = pd.to_datetime(crit["ts"], utc=True, errors="coerce")
    return bool((ts >= cutoff).any())


def _readiness_tier(pct: float) -> str:
    if pct < 5:
        return "Not Started"
    if pct < 35:
        return "Getting Started"
    if pct < 70:
        return "Building Momentum"
    return "On Track"


def _business_risk_summary(
    score: float | None, n_total: int, n_unres: int
) -> tuple[str, str]:
    if score is None or n_total == 0:
        return (
            "Not enough data yet",
            "Connect a data source and save your profile so we can estimate your level.",
        )
    if score >= 85 and n_unres == 0:
        return ("Looking good", "No open issues right now—keep your routine checks going.")
    if score >= 70:
        return ("Manageable", "Most activity is closed; review anything still open.")
    if score >= 45:
        return ("Needs attention", "Several items are still open—prioritize the list below.")
    return (
        "Elevated",
        "Multiple open items—use the Issues & Fixes page in the sidebar when you can.",
    )


def _sco_badge(label: str, kind: str) -> str:
    if kind == "pass":
        bg, fg, border = "rgba(22, 101, 52, 0.35)", "#bbf7d0", "#166534"
    elif kind == "fail":
        bg, fg, border = "rgba(127, 29, 29, 0.35)", "#fecaca", "#991b1b"
    else:
        bg, fg, border = "rgba(154, 52, 18, 0.3)", "#fed7aa", "#c2410c"
    esc = html_module.escape(label)
    return (
        f'<span style="display:inline-block;padding:6px 14px;border-radius:6px;'
        f"background:{bg};color:{fg};font-weight:800;font-size:0.85rem;"
        f'letter-spacing:0.02em;border:2px solid {border};">{esc}</span>'
    )


def _pill_html(label: str, kind: str) -> str:
    cls = "sv-sco-pill"
    if kind == "ready":
        cls += " sv-sco-pill--ready"
    elif kind == "rec":
        cls += " sv-sco-pill--rec"
    return f'<span class="{cls}">{html_module.escape(label)}</span>'


def render_security_compliance_overview(
    *,
    df: pd.DataFrame,
    data_dir: Path,
    report_org: str,
    client_risk_profile: str | None,
    client_id: str | None,
    score: float | None,
    n_res: int,
    n_unres: int,
    soc2: float,
    iso: float,
    badges: list[tuple[str, str]],
    n_controls: int,
    profile: dict | None,
    has_policy_file: bool,
    load_events_df_clear: Callable[[], None],
) -> None:
    inject_sco_page_css_once()

    onboarding_action_required = client_id is not None and (profile is None or df.empty)
    n_total = n_res + n_unres
    risk_title, risk_body = _business_risk_summary(score, n_total, n_unres)
    crit_24h = critical_open_in_last_24h(df)
    pulse_ok_1h = not critical_open_in_last_hour(df)

    if df.empty:
        status_title = "System Status: Setting up"
        status_body_html = html_module.escape(
            "We are not receiving security activity yet. When you connect a data source, "
            "this page will show a live status for your business."
        )
        dot_cls = "sv-sco-live-dot sv-sco-live-dot--warn"
    elif crit_24h:
        status_title = "System Status: Attention needed"
        status_body_html = (
            "Highest-priority open items appeared in the last day. Open "
            "<strong>Issues &amp; Fixes</strong> in the sidebar and work through the list."
        )
        dot_cls = "sv-sco-live-dot sv-sco-live-dot--warn"
    elif pulse_ok_1h:
        status_title = "System Status: Healthy"
        status_body_html = html_module.escape(
            "No highest-priority open items in the last day. Monitoring is on—we will flag "
            "anything that needs you."
        )
        dot_cls = "sv-sco-live-dot sv-sco-live-dot--ok"
    else:
        status_title = "System Status: Watch closely"
        status_body_html = (
            "A highest-priority item showed up in the last hour—open "
            "<strong>Issues &amp; Fixes</strong> to confirm it is handled."
        )
        dot_cls = "sv-sco-live-dot sv-sco-live-dot--warn"

    ws = html_module.escape((report_org or "").strip() or "Your workspace")
    st.markdown(
        f'<div class="sv-sco-page sv-sco-constrain" style="margin-bottom:0.5rem;">'
        f'<h1 class="sv-sco-h1">Security &amp; Compliance Overview</h1>'
        f'<p class="sv-sco-sub">Understand your business security posture without needing a full IT team.</p>'
        f'<p class="sv-sco-workspace">Workspace: {ws}</p></div>'
        f'<div class="sv-sco-card sv-sco-card--accent sv-sco-constrain">'
        f'<div class="sv-sco-status-row">'
        f'<div style="display:flex;gap:0.65rem;align-items:flex-start;">'
        f'<span class="{dot_cls}"></span>'
        f"<div><p class=\"sv-sco-status-title\">{html_module.escape(status_title)}</p>"
        f'<p class="sv-sco-status-body">{status_body_html}</p>'
        f'<p class="sv-sco-muted-line">SentinelView translates security activity into '
        f"plain-English business guidance.</p></div></div>"
        f'<div style="text-align:right;"><span class="sv-sco-risk-pill">Business Risk Level: '
        f"{html_module.escape(risk_title)}</span>"
        f'<p class="sv-sco-muted-line" style="margin-top:0.5rem;max-width:15rem;margin-left:auto;">'
        f"{html_module.escape(risk_body)}</p></div>"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    if client_id is not None and profile is None:
        st.caption(
            "Next: finish Compliance Setup so we can tailor scores and recommendations to your business."
        )
    elif df.empty:
        st.caption(
            "Next: bring in security activity—sample data or a connected source—so this page can update live."
        )

    evidence_today = count_evidence_items_today(data_dir, df)
    open_remediations = count_open_remediations(df)
    days_fw = days_since_framework_update(client_id)
    fw = html_module.escape(str(days_fw))

    issues_help = (
        "Nothing is waiting on you."
        if open_remediations == 0
        else "Open items are listed under Issues & Fixes."
    )
    activity_help = (
        "Security-related activity recorded today." if evidence_today else "No new activity yet—that is normal when you are getting started."
    )
    checks_help = (
        "Watches access, sensitive data, and follow-through—summaries stay in plain English."
    )
    review_help = (
        "Days since your profile or policy checklist was updated."
        if days_fw != "—"
        else "Not tracked yet. Save your profile under Compliance Setup to start the clock."
    )

    warn_class = " sv-sco-kpi-card--warn" if open_remediations > 0 else ""
    issues_icon = "⚠️" if open_remediations > 0 else "✓"

    st.markdown(
        f"""
<div class="sv-sco-kpi-grid">
  <div class="sv-sco-kpi-card">
    <div class="sv-sco-kpi-icon" aria-hidden="true">🛡️</div>
    <div class="sv-sco-kpi-label">Security Checks Running</div>
    <div class="sv-sco-kpi-value">{n_controls}</div>
    <div class="sv-sco-kpi-help">{html_module.escape(checks_help)}</div>
  </div>
  <div class="sv-sco-kpi-card">
    <div class="sv-sco-kpi-icon" aria-hidden="true">📋</div>
    <div class="sv-sco-kpi-label">Activity Logged Today</div>
    <div class="sv-sco-kpi-value">{evidence_today}</div>
    <div class="sv-sco-kpi-help">{html_module.escape(activity_help)}</div>
  </div>
  <div class="sv-sco-kpi-card{warn_class}">
    <div class="sv-sco-kpi-icon" aria-hidden="true">{issues_icon}</div>
    <div class="sv-sco-kpi-label">Issues You Need to Fix</div>
    <div class="sv-sco-kpi-value">{open_remediations}</div>
    <div class="sv-sco-kpi-help">{html_module.escape(issues_help)}</div>
  </div>
  <div class="sv-sco-kpi-card">
    <div class="sv-sco-kpi-icon" aria-hidden="true">📅</div>
    <div class="sv-sco-kpi-label">Last Security Review</div>
    <div class="sv-sco-kpi-value">{fw}</div>
    <div class="sv-sco-kpi-help">{html_module.escape(review_help)}</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    if df.empty and not onboarding_action_required:
        _empty_notice = (
            "No security activity is loaded yet. When your IT partner connects a source—or your "
            "administrator adds sample content—numbers and guidance here will update automatically."
        )
        st.markdown(
            f'<div class="sv-sco-calm-notice sv-sco-constrain">'
            f'<div class="sv-sco-calm-notice__title">What this means</div>'
            f"{html_module.escape(_empty_notice)}</div>",
            unsafe_allow_html=True,
        )

    if onboarding_action_required:
        if profile is None:
            action_title = "Finish your setup"
            action_body = (
                "Complete your compliance profile so SentinelView can calculate your risk level "
                "and recommend next steps."
            )
        else:
            action_title = "Add security activity"
            action_body = (
                "Your profile is saved. Connect a data source or load sample events so this overview "
                "and the list below can show real findings."
            )
        st.markdown(
            f"""
<div class="sv-sco-action-card sv-sco-constrain">
  <div class="sv-sco-action-title">{html_module.escape(action_title)}</div>
  <p class="sv-sco-action-body">{html_module.escape(action_body)}</p>
</div>
            """,
            unsafe_allow_html=True,
        )
        if profile is None:
            if st.button(
                "Continue Setup",
                type="primary",
                key="sv_sco_continue_setup",
                use_container_width=True,
            ):
                st.session_state["sv_primary_nav"] = "Client Onboarding Wizard"
                st.rerun()
        else:
            if st.button(
                "Open activity log",
                type="primary",
                key="sv_sco_open_activity",
                use_container_width=True,
            ):
                st.session_state["sv_primary_nav"] = "Evidence Library"
                st.rerun()

    prof_ready = profile is not None
    data_ready = not df.empty
    pol_ready = has_policy_file

    p1 = "Ready" if prof_ready else "Not Started"
    p1k = "ready" if prof_ready else "notstarted"
    p2 = "Ready" if data_ready else "Recommended"
    p2k = "ready" if data_ready else "rec"
    if pol_ready:
        p3, p3k = "Ready", "ready"
    elif prof_ready and data_ready:
        p3, p3k = "Recommended", "rec"
    else:
        p3, p3k = "Not Started", "notstarted"

    st.markdown(
        f"""
<div class="sv-sco-card sv-sco-constrain">
  <div class="sv-sco-section-title">Recommended Next Steps</div>
  <p class="sv-sco-muted-line" style="margin:0 0 0.5rem 0;">Pick one step today—even small
  progress helps you show discipline to customers and insurers.</p>
  <div class="sv-sco-rec-row">
    <div class="sv-sco-rec-icon">📝</div>
    <div class="sv-sco-rec-text"><strong>Complete your compliance profile</strong> — tells us
    what you handle so guidance matches your business.</div>
    <div>{_pill_html(p1, p1k)}</div>
  </div>
  <div class="sv-sco-rec-row">
    <div class="sv-sco-rec-icon">🔌</div>
    <div class="sv-sco-rec-text"><strong>Connect your first security data source</strong> —
    bring in activity from your tools or regular exports so this overview reflects your business.</div>
    <div>{_pill_html(p2, p2k)}</div>
  </div>
  <div class="sv-sco-rec-row">
    <div class="sv-sco-rec-icon">📄</div>
    <div class="sv-sco-rec-text"><strong>Generate your first policy document</strong> —
    export plain-language policies you can share with auditors.</div>
    <div>{_pill_html(p3, p3k)}</div>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    _primary_compliance = profile is None
    _primary_activity = profile is not None and df.empty
    c_go1, c_go2, c_go3 = st.columns(3)
    with c_go1:
        if st.button(
            "Go to Compliance Setup",
            key="sco_go_wiz",
            type="primary" if _primary_compliance else "secondary",
            use_container_width=True,
        ):
            st.session_state["sv_primary_nav"] = "Client Onboarding Wizard"
            st.rerun()
    with c_go2:
        if st.button(
            "View Activity Log",
            key="sco_go_evd",
            type="primary" if _primary_activity else "secondary",
            use_container_width=True,
        ):
            st.session_state["sv_primary_nav"] = "Evidence Library"
            st.rerun()
    with c_go3:
        if st.button("Open Policies", key="sco_go_pol", type="secondary", use_container_width=True):
            st.session_state["sv_primary_nav"] = "Policy Generator"
            st.rerun()

    st.markdown(
        '<p class="sv-sco-section-title sv-sco-constrain" style="margin-top:0.75rem;">'
        "Compliance Readiness</p>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Percentages reflect checklist items you have marked complete in SentinelView—they are "
        "a working guide, not a formal audit or certification."
    )
    soc_tier = _readiness_tier(soc2)
    iso_tier = _readiness_tier(iso)
    st.markdown(
        f"""
<div class="sv-sco-readiness-card sv-sco-constrain">
  <div class="sv-sco-readiness-line">
    <span class="sv-sco-readiness-label">SOC 2 Readiness</span>
    <span class="sv-sco-readiness-tier">{html_module.escape(soc_tier)}</span>
    <span class="sv-sco-readiness-pct">{soc2:.0f}%</span>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(min(1.0, max(0.0, soc2 / 100.0)))
    st.markdown(
        f"""
<div class="sv-sco-readiness-card sv-sco-constrain" style="margin-top:0.5rem;">
  <div class="sv-sco-readiness-line">
    <span class="sv-sco-readiness-label">ISO 27001 Readiness</span>
    <span class="sv-sco-readiness-tier">{html_module.escape(iso_tier)}</span>
    <span class="sv-sco-readiness-pct">{iso:.0f}%</span>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(min(1.0, max(0.0, iso / 100.0)))

    if client_id:
        if st.button(
            "Open security questionnaire (optional)",
            type="secondary",
            key="sco_open_policy_checklist",
        ):
            st.session_state["sv_primary_nav"] = "Onboarding"
            st.rerun()

    st.markdown(
        '<p class="sv-sco-section-title sv-sco-constrain" style="margin-top:1.25rem;">'
        "What we&apos;re checking for you</p>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Plain-language status for the safeguards we monitor on your behalf (access, data, backups, and similar checks)."
    )
    cols = st.columns(min(3, len(badges)))
    for i, (label, kind) in enumerate(badges):
        with cols[i % len(cols)]:
            lab = (
                "On track"
                if kind == "pass"
                else ("Needs work" if kind == "fail" else "Review suggested")
            )
            st.markdown(
                f'<div style="margin-bottom:0.35rem;">{_sco_badge(lab, kind)}</div>'
                f'<div style="font-size:0.9rem;font-weight:600;color:#475569;">{html_module.escape(label)}</div>',
                unsafe_allow_html=True,
            )

    st.divider()
    st.markdown(
        '<p class="sv-sco-section-title sv-sco-constrain">Items that need your attention</p>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Resolve or acknowledge each item here—SentinelView keeps a dated record you can show in a customer or insurer review."
    )
    render_actionable_alert_feed(
        df,
        data_dir,
        client_risk_profile,
        key_ns="security_overview",
        load_events_df_clear=load_events_df_clear,
    )
