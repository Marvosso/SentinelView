"""
Policy-to-Evidence bridge — maps generated policies to SIEM-backed event channels.

Visualizes closed-loop compliance: written policy (left) ↔ interpreted logs (right).
"""

from __future__ import annotations

import html as html_module
from typing import Any

import pandas as pd
import streamlit as st

POLICY_CHANNEL_META: dict[str, tuple[str | None, str]] = {
    "Data Handling Policy": (
        "privacy_scan",
        "Maps to **privacy_scan** interpretations (PII / exposure posture). "
        "Resolved items show disposition recorded in SQLite.",
    ),
    "Access Control Policy": (
        "access_review",
        "Maps to **access_review** interpretations (roster-aligned privileged access). "
        "Preference order: recently **resolved** closures, then newest open detections.",
    ),
    "Incident Response Plan": (
        "__all__",
        "Spans all ingested SentinelView channels — detection through disposition.",
    ),
}


def _row_resolved(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def slice_evidence_for_policy(
    df: pd.DataFrame,
    policy_title: str,
    *,
    limit: int = 5,
) -> pd.DataFrame:
    """
    Rows that substantiate the policy in the SIEM store.

    Access / Data policies: prefer **resolved** rows first (closed-loop proof), then
    backfill with newest open signals so the feed is never empty when activity exists.
    """
    if df.empty or policy_title not in POLICY_CHANNEL_META:
        return pd.DataFrame()

    channel, _ = POLICY_CHANNEL_META[policy_title]

    if channel == "__all__":
        sub = df.copy()
    elif channel:
        sub = df[df["source_log"] == channel].copy()
    else:
        sub = df.copy()

    if sub.empty:
        return sub

    sub = sub.assign(_ts=pd.to_datetime(sub["ts"], utc=True, errors="coerce"))
    sub = sub.sort_values("_ts", ascending=False)

    if channel == "__all__":
        out = sub.head(limit).drop(columns=["_ts"], errors="ignore")
        return out

    sub["_res"] = sub["resolved"].map(_row_resolved)
    resolved = sub[sub["_res"]].drop(columns=["_res"])
    open_ = sub[~sub["_res"]].drop(columns=["_res"])

    resolved_part = resolved.head(limit)
    need = limit - len(resolved_part)
    open_part = open_.head(need) if need > 0 else pd.DataFrame()

    if resolved_part.empty and open_part.empty:
        return pd.DataFrame()

    out = pd.concat([resolved_part, open_part], ignore_index=True).head(limit)
    return out.drop(columns=["_ts"], errors="ignore")


def render_policy_evidence_bridge(
    policies: dict[str, str],
    df: pd.DataFrame,
    *,
    client_id: str,
) -> None:
    """Split layout: policy Markdown | SIEM evidence cards."""
    if not policies:
        return

    st.divider()
    st.subheader("Policy-to-Evidence bridge")
    st.caption(
        "Closed-loop compliance: **policy intent** on the left, **live interpreted SIEM signals** "
        "from your SentinelView store on the right — same posture, technical proof."
    )

    titles = list(policies.keys())
    choice = st.selectbox(
        "Policy for split view",
        options=titles,
        key=f"sv_policy_bridge_pick_{client_id}",
        help="Each policy maps to detection channels stored in `sentinelview_events.sqlite`.",
    )

    _, meta_desc = POLICY_CHANNEL_META.get(
        choice, (None, "Mapped detection channels from stored events.")
    )

    left, right = st.columns(2, gap="large")

    with left:
        st.markdown("##### Plain English policy")
        st.caption("Generated from your client profile (Policy Generation Engine).")
        st.markdown(policies[choice])

    with right:
        st.markdown("##### SIEM evidence feed")
        st.caption(meta_desc)

        slice_df = slice_evidence_for_policy(df, choice, limit=5)

        if slice_df.empty:
            st.info(
                "No matching events in the database yet. Run **ingest_engine** so "
                "`access_review` / `privacy_scan` CSVs are interpreted into SQLite — "
                "then this panel shows the last closures and detections that prove controls "
                "are operating."
            )
            return

        display_cols = [
            c
            for c in (
                "ts",
                "source_log",
                "risk_level",
                "summary",
                "resolved",
                "event_id",
            )
            if c in slice_df.columns
        ]
        for _, row in slice_df[display_cols].iterrows():
            ts = str(row.get("ts", ""))[:19]
            src = html_module.escape(str(row.get("source_log", "")))
            risk = html_module.escape(str(row.get("risk_level", "")))
            summ = html_module.escape(str(row.get("summary", ""))[:220])
            res = _row_resolved(row.get("resolved"))
            eid = html_module.escape(str(row.get("event_id", "")))
            status_html = (
                '<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:999px;'
                'font-size:0.7rem;font-weight:700;">CLOSED LOOP</span>'
                if res
                else '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:999px;'
                'font-size:0.7rem;font-weight:700;">OPEN</span>'
            )
            st.markdown(
                f'<div style="background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:0.85rem 1rem;'
                f'margin-bottom:0.65rem;box-shadow:0 1px 3px rgba(15,23,42,0.05);">'
                f'<div style="font-size:0.72rem;color:#64748b;font-weight:600;">{ts} UTC · '
                f'<code style="font-size:0.72rem;">{src}</code></div>'
                f'<div style="margin:0.35rem 0;font-weight:700;color:#0f172a;">{summ}</div>'
                f'<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.35rem;">'
                f'<span style="font-size:0.75rem;color:#475569;">Risk: <strong>{risk}</strong> · '
                f'<span style="font-family:monospace;font-size:0.72rem;">{eid}</span></span>'
                f"{status_html}</div></div>",
                unsafe_allow_html=True,
            )

        st.caption(
            "_Showing up to 5 rows — preferring resolved items when available "
            "(demonstrates disposition against policy)._"
        )
