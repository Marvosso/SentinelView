"""
Premium SaaS-style Trust Center UI — CSS, pulse header, KPI tiles, actionable alert feed.
"""

from __future__ import annotations

import html as html_module
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pandas as pd
import streamlit as st

from audit_evidence_package import list_resolved_evidence_files
from client_profile import client_profile_path
from event_db import set_acknowledged, set_resolution
from onboarding_policy import client_policy_path_for_client
from response_tracking import remediation_step_choices, widget_key_safe

# Override with env SENTINELVIEW_MANAGED_BY="Your MSP Name"
MANAGED_BY_BRAND = (os.environ.get("SENTINELVIEW_MANAGED_BY") or "SentinelView").strip()

def _theme_is_dark() -> bool:
    try:
        theme = getattr(st.context, "theme", None)
        if theme is not None:
            return getattr(theme, "base", "light") == "dark"
    except Exception:
        pass
    return False


def _sentinelview_theme_variables() -> str:
    if _theme_is_dark():
        return """
:root {
  --sv-bg: #0E1117;
  --sv-card: #1A1C24;
  --sv-card-muted: #161821;
  --sv-border: #2D2E35;
  --sv-text: #f8fafc;
  --sv-text-strong: #ffffff;
  --sv-muted: #94a3b8;
  --sv-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.35);
  --sv-cyber: #00D4FF;
  --sv-emerald-glow: rgba(16, 185, 129, 0.45);
  --sv-header-bg: rgba(14, 17, 23, 0.92);
  --sv-zebra: rgba(255, 255, 255, 0.04);
  --sv-gauge-hole: #1A1C24;
  --sv-gauge-track: #2D2E35;
}
"""
    return """
:root {
  --sv-bg: #F8FAFC;
  --sv-card: #FFFFFF;
  --sv-card-muted: #f1f5f9;
  --sv-border: #E2E8F0;
  --sv-text: #0f172a;
  --sv-text-strong: #0f172a;
  --sv-muted: #64748b;
  --sv-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
  --sv-cyber: #00D4FF;
  --sv-emerald-glow: rgba(16, 185, 129, 0.55);
  --sv-header-bg: rgba(248, 250, 252, 0.92);
  --sv-zebra: rgba(15, 23, 42, 0.04);
  --sv-gauge-hole: #f8fafc;
  --sv-gauge-track: #e2e8f0;
}
"""


TRUST_CENTER_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html {
  font-size: 16px;
}
html, body, [class*="stApp"] {
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif !important;
}
[data-testid="stAppViewContainer"] {
  background: var(--sv-bg) !important;
  color: var(--sv-text);
}
[data-testid="stHeader"] {
  background: var(--sv-header-bg) !important;
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--sv-border) !important;
}
section[data-testid="stSidebar"] {
  background: var(--sv-bg) !important;
  border-right: 1px solid var(--sv-border) !important;
}
[data-testid="stSidebar"] .block-container {
  padding-top: 1rem;
}

/* Sidebar: text-style nav (tertiary buttons), not boxy */
[data-testid="stSidebar"] button[kind="tertiary"] {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  color: var(--sv-text) !important;
  font-weight: 500 !important;
  justify-content: flex-start !important;
  padding: 0.4rem 0.5rem 0.4rem 0.25rem !important;
  border-radius: 8px !important;
  width: 100%;
}
[data-testid="stSidebar"] button[kind="tertiary"]:hover {
  color: var(--sv-cyber) !important;
  background: rgba(0, 212, 255, 0.08) !important;
}
.sv-nav-accent-bar {
  display: block;
  width: 4px;
  min-height: 1.75rem;
  border-radius: 3px;
  background: var(--sv-cyber);
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.35);
  margin-top: 0.2rem;
}
.sv-nav-accent-spacer {
  display: block;
  width: 4px;
  min-height: 1.75rem;
  margin-top: 0.2rem;
}
.sv-nav-group-label {
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--sv-muted);
  margin: 1.1rem 0 0.4rem 0;
  text-transform: uppercase;
}
.sv-nav-group-label:first-of-type {
  margin-top: 0.35rem;
}

/* Connection status badge */
.sv-status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--sv-text);
  margin-top: 0.35rem;
}
.sv-status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.55);
  animation: sv-status-pulse 2s ease-in-out infinite;
}
@keyframes sv-status-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.45); transform: scale(1); }
  50% { box-shadow: 0 0 12px 4px rgba(34, 197, 94, 0.35); transform: scale(1.05); }
}

/* Metrics & cards */
[data-testid="stMetric"] {
  background: var(--sv-card) !important;
  border: 1px solid var(--sv-border) !important;
  border-radius: 12px !important;
  padding: 0.75rem 1rem !important;
  box-shadow: var(--sv-shadow) !important;
}
[data-testid="stMetric"] label {
  color: var(--sv-muted) !important;
  font-size: 0.78rem !important;
  font-weight: 600 !important;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
  color: var(--sv-text-strong) !important;
  font-size: 2rem !important;
  font-weight: 800 !important;
}
.sv-kpi-card {
  background: var(--sv-card);
  border: 1px solid var(--sv-border);
  border-radius: 12px;
  padding: 0.85rem 1rem;
  min-height: 5.5rem;
  box-shadow: var(--sv-shadow);
}
.sv-kpi-card--emerald {
  border-color: rgba(16, 185, 129, 0.35);
  box-shadow: var(--sv-shadow), 0 0 0 1px rgba(16, 185, 129, 0.12);
}
.sv-kpi-label {
  font-size: 0.78rem;
  color: var(--sv-muted);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.sv-kpi-value {
  font-size: 2rem;
  font-weight: 800;
  line-height: 1.2;
  margin: 0.25rem 0;
  color: var(--sv-text-strong);
}
.sv-kpi-sub {
  font-size: 0.8rem;
  color: var(--sv-muted);
  font-weight: 500;
}

/* Pulse banner & dot */
.sv-pulse-wrap { display: inline-flex; align-items: center; gap: 0.5rem; }
.sv-pulse-dot {
  width: 12px; height: 12px; border-radius: 50%;
  display: inline-block;
}
.sv-pulse-ok {
  background: #22c55e;
  animation: sv-pulse-glow-soft 2s ease-in-out infinite;
}
.sv-pulse-warn {
  background: #ef4444;
  animation: sv-pulse-glow-warn 2s ease-in-out infinite;
}
@keyframes sv-pulse-glow-soft {
  0%, 100% {
    box-shadow: 0 0 4px rgba(34, 197, 94, 0.35), 0 0 0 0 rgba(34, 197, 94, 0.4);
    filter: brightness(1);
  }
  50% {
    box-shadow: 0 0 18px rgba(34, 197, 94, 0.55), 0 0 24px rgba(34, 197, 94, 0.25);
    filter: brightness(1.06);
  }
}
@keyframes sv-pulse-glow-warn {
  0%, 100% { box-shadow: 0 0 4px rgba(239, 68, 68, 0.45); }
  50% { box-shadow: 0 0 16px rgba(239, 68, 68, 0.55); }
}
.sv-tc-pulse-banner {
  background: var(--sv-card);
  border: 1px solid var(--sv-border);
  border-radius: 16px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1rem;
  box-shadow: var(--sv-shadow);
}
.sv-tc-score { font-size: 2.25rem; font-weight: 800; color: var(--sv-text-strong); letter-spacing: -0.03em; }
.sv-tc-sub { font-size: 0.85rem; color: var(--sv-muted); font-weight: 600; }
.sv-pulse-label { font-weight: 700; color: var(--sv-text); font-size: 0.95rem; }

/* Hero audit banner */
.sv-hero-shell {
  background: linear-gradient(135deg, #2563eb 0%, #4f46e5 55%, #7c3aed 100%);
  border-radius: 12px;
  padding: 1.15rem 1.35rem;
  margin-bottom: 0.65rem;
  box-shadow: var(--sv-shadow);
  border: 1px solid rgba(255, 255, 255, 0.15);
}
.sv-hero-kicker {
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: rgba(255, 255, 255, 0.85);
  margin-bottom: 0.35rem;
}
.sv-hero-headline {
  font-size: 1.25rem;
  font-weight: 800;
  color: #ffffff;
  letter-spacing: -0.02em;
  line-height: 1.3;
}

/* Scanning / idle gauge */
.sv-gauge-scan-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}
.sv-gauge-scan {
  position: relative;
  width: 200px;
  height: 200px;
}
.sv-gauge-scan-ring {
  position: absolute;
  inset: 0;
  z-index: 0;
  border-radius: 50%;
  background: conic-gradient(from 0deg, var(--sv-cyber), #a855f7, #6366f1, var(--sv-cyber));
  animation: sv-scan-spin 2.5s linear infinite;
  opacity: 0.9;
  transform-origin: 50% 50%;
}
.sv-gauge-scan-ring-inner {
  position: absolute;
  inset: 10px;
  z-index: 1;
  border-radius: 50%;
  background: var(--sv-gauge-hole);
  border: 1px solid var(--sv-border);
}
.sv-gauge-scan-center {
  position: absolute;
  inset: 28px;
  z-index: 2;
  border-radius: 50%;
  background: var(--sv-card);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: inset 0 0 0 1px var(--sv-border);
}
.sv-gauge-scan-title {
  font-size: 1.05rem;
  font-weight: 800;
  color: var(--sv-text-strong);
  letter-spacing: 0.02em;
}
.sv-gauge-scan-sub {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--sv-muted);
  margin-top: 0.25rem;
}
@keyframes sv-scan-spin {
  to { transform: rotate(360deg); }
}

/* Compliance ring gauge (data present) */
.sv-gauge-root {
  position: relative;
  width: 200px;
  height: 200px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.sv-gauge-outer {
  position: absolute;
  inset: 0;
  z-index: 0;
  border-radius: 50%;
  box-shadow: inset 0 0 0 4px var(--sv-border);
}
.sv-gauge-hole {
  position: absolute;
  inset: 18px;
  z-index: 1;
  border-radius: 50%;
  background: var(--sv-gauge-hole);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.1);
}
.sv-gauge-pct {
  font-size: 2.25rem;
  font-weight: 800;
  color: var(--sv-text-strong);
  line-height: 1;
}
.sv-gauge-sub {
  font-size: 0.9rem;
  font-weight: 700;
  color: var(--sv-muted);
}

.sv-alert-card {
  background: var(--sv-card);
  border: 1px solid var(--sv-border);
  border-radius: 12px;
  padding: 1rem 1.15rem;
  margin-bottom: 0.85rem;
  box-shadow: var(--sv-shadow);
}
.sv-risk-pill {
  display: inline-block;
  padding: 0.2rem 0.65rem;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.sv-managed-footer {
  font-size: 0.72rem;
  color: var(--sv-muted);
  font-weight: 600;
  text-align: center;
  margin-top: 1.5rem;
  padding: 0.75rem 0.5rem;
  border-top: 1px solid var(--sv-border);
}
.sv-sop-panel {
  background: var(--sv-card-muted);
  border: 1px solid var(--sv-border);
  border-radius: 12px;
  padding: 0.9rem 1rem 1rem 1rem;
  border-left: 4px solid #2563eb;
  box-shadow: var(--sv-shadow);
  min-height: 8rem;
}
.sv-evidence-pulse-badge {
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--sv-muted);
}
.sv-fw-section-title {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--sv-muted);
  margin: 0 0 0.6rem 0;
}

/* Brand block in sidebar */
.sv-brand {
  font-family: 'Inter', system-ui, sans-serif !important;
  font-weight: 800 !important;
  font-size: 1.35rem !important;
  letter-spacing: -0.02em !important;
  color: var(--sv-text-strong) !important;
  margin: 0 !important;
}
.sv-brand-sub {
  font-size: 0.78rem !important;
  font-weight: 600 !important;
  margin-top: 0.15rem !important;
  text-transform: uppercase !important;
  letter-spacing: 0.06em !important;
  color: var(--sv-muted) !important;
}

/* Data tables: zebra, no vertical grid */
[data-testid="stDataFrame"] table tbody tr:nth-child(even) td,
[data-testid="stDataFrame"] table tbody tr:nth-child(even) th {
  background-color: var(--sv-zebra) !important;
}
[data-testid="stDataFrame"] table td,
[data-testid="stDataFrame"] table th {
  border-right: none !important;
  border-color: var(--sv-border) !important;
}
[data-testid="stDataFrame"] [role="grid"] [role="row"]:nth-child(even) [role="gridcell"],
[data-testid="stDataFrame"] [role="row"]:nth-child(even) [role="gridcell"] {
  background-color: var(--sv-zebra) !important;
}
[data-testid="stDataFrame"] [role="gridcell"] {
  border-right: none !important;
}

/* Onboarding CTA card (theme-aware) */
.sv-onboarding-cta {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, var(--sv-card) 100%);
  border: 1px solid rgba(245, 158, 11, 0.35);
  border-radius: 16px;
  padding: 1.25rem 1.35rem;
  min-height: 200px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  box-sizing: border-box;
  border-left: 4px solid #d97706;
  box-shadow: var(--sv-shadow);
}
.sv-onboarding-cta-kicker {
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #d97706;
  margin-bottom: 0.5rem;
}
.sv-onboarding-cta-body {
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--sv-text);
  margin: 0;
  line-height: 1.45;
}

/* Framework panel inside Trust Center */
[data-testid="stVerticalBlockBorderWrapper"] {
  border-radius: 12px !important;
}

/* Progress bars */
[data-testid="stProgress"],
[data-testid="stProgressBar"] {
  margin-top: 0.35rem;
  margin-bottom: 0.15rem;
}
[data-testid="stProgress"] [data-baseweb="progress-bar"] > div > div,
[data-testid="stProgressBar"] [data-baseweb="progress-bar"] > div > div {
  min-height: 8px;
  height: 8px !important;
  border-radius: 9999px !important;
  background-color: var(--sv-gauge-track) !important;
  box-shadow: inset 0 1px 2px rgba(15, 23, 42, 0.08);
}
[data-testid="stProgress"] [data-baseweb="progress-bar"] > div > div > div,
[data-testid="stProgressBar"] [data-baseweb="progress-bar"] > div > div > div {
  border-radius: 9999px !important;
  background: linear-gradient(90deg, #059669, #10b981) !important;
}
"""


def inject_trust_center_theme() -> None:
    st.markdown(
        f"<style>{_sentinelview_theme_variables()}{TRUST_CENTER_CSS}</style>",
        unsafe_allow_html=True,
    )


def render_audit_ready_hero(*, key_prefix: str = "sv_hero") -> None:
    """Premium gradient CTA — tenant workspaces only (caller checks client)."""
    st.markdown(
        """
        <div class="sv-hero-shell">
          <div class="sv-hero-kicker">Onboarding progress</div>
          <div class="sv-hero-headline">Ready to Pass Your Next Audit?</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button(
        "Finish Setup",
        type="primary",
        key=f"{key_prefix}_finish_setup",
        use_container_width=True,
    ):
        st.session_state["sv_primary_nav"] = "Client Onboarding Wizard"
        st.rerun()


def _utc_today() -> datetime.date:
    return datetime.now(timezone.utc).date()


def _row_resolved(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def critical_open_in_last_hour(df: pd.DataFrame) -> bool:
    """True if any unresolved Critical event has ts within the last hour (UTC)."""
    if df.empty or "risk_level" not in df.columns or "ts" not in df.columns:
        return False
    d = df.copy()
    d["_open"] = ~d["resolved"].map(_row_resolved) if "resolved" in d.columns else True
    crit = d[(d["risk_level"] == "Critical") & (d["_open"])]
    if crit.empty:
        return False
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    ts = pd.to_datetime(crit["ts"], utc=True, errors="coerce")
    return bool((ts >= cutoff).any())


def count_evidence_items_today(data_dir: Path, df: pd.DataFrame) -> int:
    today = _utc_today()
    n = 0
    try:
        for p in list_resolved_evidence_files(data_dir):
            try:
                mt = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).date()
                if mt == today:
                    n += 1
            except OSError:
                continue
    except OSError:
        pass
    if n == 0 and not df.empty and "ts" in df.columns:
        ts = pd.to_datetime(df["ts"], utc=True, errors="coerce")
        n = int((ts.dt.date == today).sum())
    return n


def count_open_remediations(df: pd.DataFrame) -> int:
    if df.empty or "resolved" not in df.columns:
        return 0
    return int((~df["resolved"].map(_row_resolved)).sum())


def days_since_framework_update(client_id: str | None, cwd: Path | None = None) -> str:
    """Best-effort: days since client_profile or client_policy JSON was updated."""
    dates: list[datetime] = []
    if client_id:
        for loader in (
            lambda: _json_updated_at(client_profile_path(client_id, cwd)),
            lambda: _json_updated_at(client_policy_path_for_client(client_id, cwd)),
        ):
            dt = loader()
            if dt:
                dates.append(dt)
    if not dates:
        return "—"
    latest = max(dates)
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    else:
        latest = latest.astimezone(timezone.utc)
    delta = datetime.now(timezone.utc) - latest
    return str(max(0, delta.days))


def _json_updated_at(path: Path) -> datetime | None:
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = doc.get("updated_at")
    if not raw:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def render_pulse_header(
    *,
    compliance_pct: float | None,
    n_res: int,
    n_total: int,
    pulse_ok: bool,
) -> None:
    score_txt = f"{compliance_pct:.0f}%" if compliance_pct is not None else "—"
    sub = (
        f"{n_res} resolved · {n_total} total events"
        if n_total
        else "Add security activity to compute posture"
    )
    pulse_class = "sv-pulse-ok" if pulse_ok else "sv-pulse-warn"
    pulse_label = "Evidence pulse — live" if pulse_ok else "Evidence pulse — review"
    pulse_detail = (
        "Live check: no highest-severity open items in the past hour (UTC). "
        "Monitoring is active—not a one-time report."
        if pulse_ok
        else "Live check: highest-severity open items appeared in the past hour—"
        "confirm someone is looking into them."
    )
    st.markdown(
        f"""
        <div class="sv-tc-pulse-banner">
          <div class="sv-evidence-pulse-badge" style="margin-bottom:0.5rem;">Evidence pulse</div>
          <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:1rem;">
            <div>
              <div class="sv-tc-sub">Compliance health score</div>
              <div class="sv-tc-score">{html_module.escape(score_txt)}</div>
              <div class="sv-tc-sub">{html_module.escape(sub)}</div>
            </div>
            <div style="text-align:right;">
              <div class="sv-pulse-wrap">
                <span class="sv-pulse-dot {pulse_class}"></span>
                <span class="sv-pulse-label">{html_module.escape(pulse_label)}</span>
              </div>
              <div class="sv-tc-sub" style="margin-top:0.35rem;max-width:22rem;margin-left:auto;">
                {html_module.escape(pulse_detail)}</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpi_tile_row(
    *,
    n_controls: int,
    evidence_today: int,
    open_remediations: int,
    days_framework: str,
) -> None:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total controls monitored", str(n_controls))
    with c2:
        st.metric("Evidence items (today)", str(evidence_today))
    with c3:
        rem_var = "#b91c1c" if open_remediations > 0 else "var(--sv-text-strong)"
        rem_sub = "Needs action" if open_remediations > 0 else "Clear"
        em_class = " sv-kpi-card--emerald" if open_remediations == 0 else ""
        st.markdown(
            f"""
            <div class="sv-kpi-card{em_class}">
              <div class="sv-kpi-label">Open remediations</div>
              <div class="sv-kpi-value" style="color:{rem_var};">{open_remediations}</div>
              <div class="sv-kpi-sub">{rem_sub}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.metric("Days since last framework update", str(days_framework))


def _plain_english_sop_markdown(row: object) -> str:
    """Side-panel copy: prescribed steps + resolution codes for this detection."""
    src = str(row.get("source_log", "")) if hasattr(row, "get") else ""
    risk = str(row.get("risk_level", "")) if hasattr(row, "get") else ""
    rem = str(row.get("remediation", "") or "—") if hasattr(row, "get") else "—"
    lines = [
        f"**Detection channel:** `{src}`  ",
        f"**Severity:** {risk}",
        "",
        "**Prescribed remediation:**",
        rem,
        "",
        "**When you resolve — pick one disposition:**",
    ]
    for opt in remediation_step_choices(src, risk):
        lines.append(f"- {opt}")
    lines.extend(
        [
            "",
            "_This panel mirrors auditor-friendly plain-language guidance—use it while "
            "recording the fix in SentinelView._",
        ]
    )
    return "\n".join(lines)


def _risk_pill_style(risk: str) -> str:
    if risk == "Critical":
        return "background:#fee2e2;color:#991b1b;border:1px solid #fecaca;"
    if risk == "High":
        return "background:#fef9c3;color:#854d0e;border:1px solid #fde047;"
    return "background:#e2e8f0;color:#475569;border:1px solid #cbd5e1;"


def render_actionable_alert_feed(
    df: pd.DataFrame,
    data_dir: Path,
    client_risk_profile: str | None,
    *,
    key_ns: str,
    load_events_df_clear: Callable[[], None],
) -> None:
    """
    Card-based urgent queue with remediation visible; Resolve records disposition for audit.
    """
    _ = client_risk_profile  # reserved for future profile-weighted feed copy

    if df.empty:
        if key_ns == "security_overview":
            _msg = (
                "No items need your attention yet. When security activity is connected, prioritized "
                "findings will appear here with plain-English recommended fixes."
            )
            st.markdown(
                f'<div class="sv-sco-calm-notice sv-sco-constrain">'
                f'<div class="sv-sco-calm-notice__title">Nothing queued</div>'
                f"{html_module.escape(_msg)}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.info(
                "No security findings are loaded yet. Add data using your provider's export, your "
                "MSP's connection, or the project's data loader—then events will appear here."
            )
        return

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
        if key_ns == "security_overview":
            _clear = (
                "There are no urgent items in your queue. SentinelView will surface anything "
                "that needs a decision here."
            )
            st.markdown(
                f'<div class="sv-sco-calm-notice sv-sco-calm-notice--settled sv-sco-constrain">'
                f'<div class="sv-sco-calm-notice__title">All clear</div>'
                f"{html_module.escape(_clear)}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.success("No urgent findings right now—the highest-severity queue is clear.")
        return

    st.markdown("##### Actionable alert feed")
    st.caption(
        "Suggested fix on the left, step-by-step guidance on the right—no policy PDF hunt required."
    )

    for _, row in urgent.iterrows():
        eid = str(row["event_id"])
        risk = str(row.get("risk_level", ""))
        summ = str(row.get("summary", ""))
        rem = str(row.get("remediation", "") or "—")
        detail = str(row.get("detail", "") or "")
        summ_e = html_module.escape(summ)
        rem_e = html_module.escape(rem)
        try:
            ack = int(row.get("acknowledged") or 0) != 0
        except (TypeError, ValueError):
            ack = bool(row.get("acknowledged"))
        res = bool(row.get("resolved", False))
        pill = _risk_pill_style(risk)

        col_alert, col_sop = st.columns([1.22, 1], gap="large")

        with col_alert:
            st.markdown(
                f'<div class="sv-alert-card">'
                f'<span class="sv-risk-pill" style="{pill}">{html_module.escape(risk)}</span>'
                f" <strong style='color:#0f172a;font-size:1rem;'>{summ_e}</strong>"
                f"<p style='color:#475569;margin:0.65rem 0 0.35rem;font-size:0.9rem;'>"
                f"<strong>Fix:</strong> {rem_e}</p>"
                f"</div>",
                unsafe_allow_html=True,
            )
            if detail:
                cap = detail[:280] + ("…" if len(detail) > 280 else "")
                st.caption(html_module.escape(cap))

            b1, b2 = st.columns([1, 2])
            with b1:
                if not ack and not res:
                    if st.button(
                        "Acknowledge",
                        key=widget_key_safe(f"{key_ns}_{eid}", "ack"),
                        type="secondary",
                    ):
                        set_acknowledged(eid, data_dir)
                        load_events_df_clear()
                        st.rerun()
                elif ack and not res:
                    st.caption(f"Acknowledged · {row.get('acknowledged_at') or '—'}")
                elif res:
                    st.success("Resolved")
            with b2:
                if res:
                    st.markdown(
                        f"_Resolved at:_ `{row.get('resolved_at') or '—'}` · "
                        f"_Step:_ {row.get('remediation_step_taken') or '—'}"
                    )
                else:
                    opts = remediation_step_choices(
                        str(row.get("source_log", "")),
                        str(row.get("risk_level", "")),
                    )
                    with st.form(key=widget_key_safe(f"{key_ns}_{eid}", "resolve_form")):
                        step = st.selectbox(
                            "Remediation step",
                            options=opts,
                            key=widget_key_safe(f"{key_ns}_{eid}", "step_pick"),
                        )
                        notes = st.text_area(
                            "Notes (optional)",
                            key=widget_key_safe(f"{key_ns}_{eid}", "res_notes"),
                            height=56,
                        )
                        attest_name = st.text_input(
                            "Attested by (optional)",
                            key=widget_key_safe(f"{key_ns}_{eid}", "attest_name"),
                            placeholder="Name or ID",
                        )
                        attest_role = st.text_input(
                            "Role (optional)",
                            key=widget_key_safe(f"{key_ns}_{eid}", "attest_role"),
                            placeholder="e.g. Security Lead",
                        )
                        submitted = st.form_submit_button(
                            "Resolve",
                            type="primary",
                        )
                        if submitted:
                            set_resolution(
                                eid,
                                remediation_step=step,
                                resolution_notes=notes,
                                data_dir=data_dir,
                                attested_by=(attest_name or "").strip() or None,
                                attester_role=(attest_role or "").strip() or None,
                            )
                            load_events_df_clear()
                            st.rerun()

        with col_sop:
            st.markdown('<div class="sv-sop-panel">', unsafe_allow_html=True)
            st.markdown("##### Plain English SOP · side panel")
            st.caption("Instant remediation guidance for this detection.")
            st.markdown(_plain_english_sop_markdown(row))
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='height:0.65rem'></div>", unsafe_allow_html=True)


def render_sidebar_managed_footer() -> None:
    safe = html_module.escape(MANAGED_BY_BRAND)
    st.markdown(
        f'<p class="sv-managed-footer">Managed by <strong>{safe}</strong><br/>'
        "<span style='font-weight:500;color:#cbd5e1;'>Compliance as a Service</span></p>",
        unsafe_allow_html=True,
    )
