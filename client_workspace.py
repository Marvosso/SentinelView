"""
SentinelView — Multi-tenant client workspaces.

Each client lives under ``<project>/clients/<client_id>/`` with:

- ``data/`` — event store (``sentinelview_events.sqlite``, audit evidence packages)
- ``logs/`` — CSV drop zone for ingestion (``access_review.csv``, ``privacy_scan.csv``, …)

Run ingestion per client, for example::

    py -3 ingest_engine.py clients/acme_corp/logs --data-dir clients/acme_corp/data --settings settings.yaml
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from event_db import init_db, load_events_rows

GLOBAL_CLIENT_LABEL = "— Global (all clients) —"


def workspace_root(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()).resolve()


def clients_root(cwd: Path | None = None) -> Path:
    return workspace_root(cwd) / "clients"


def list_registered_clients(cwd: Path | None = None) -> list[str]:
    """Subfolder names under ``clients/`` (each treated as one SMB client)."""
    root = clients_root(cwd)
    if not root.is_dir():
        return []
    out: list[str] = []
    for p in sorted(root.iterdir()):
        if p.is_dir() and not p.name.startswith("."):
            out.append(p.name)
    return out


def client_data_dir(client_id: str, cwd: Path | None = None) -> Path:
    return clients_root(cwd) / client_id / "data"


def client_logs_dir(client_id: str, cwd: Path | None = None) -> Path:
    return clients_root(cwd) / client_id / "logs"


def ensure_client_layout(client_id: str, cwd: Path | None = None) -> tuple[Path, Path]:
    """Create ``data/`` and ``logs/`` for a client; return ``(data_dir, logs_dir)``."""
    d = client_data_dir(client_id, cwd)
    lg = client_logs_dir(client_id, cwd)
    d.mkdir(parents=True, exist_ok=True)
    lg.mkdir(parents=True, exist_ok=True)
    return d, lg


def _row_resolved(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val in (0, 1, "0", "1"):
        return bool(int(val))
    return bool(val)


def load_events_dataframe(data_dir: Path) -> pd.DataFrame:
    """Load security events from SQLite under ``data_dir`` (same shape as dashboard)."""
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


def compliance_pct(df: pd.DataFrame) -> float | None:
    n = len(df)
    if n == 0:
        return None
    resolved = int(df["resolved"].sum())
    return 100.0 * resolved / n


def build_global_risk_summary(cwd: Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Aggregate metrics across every client folder.

    Returns:
        ``summary``: one row per client — critical open, high open, total events,
                     compliance %, last event time.
        ``critical_open``: all **open** Critical rows with ``client_id`` column.
    """
    ids = list_registered_clients(cwd)
    summary_rows: list[dict[str, Any]] = []
    crit_parts: list[pd.DataFrame] = []

    for cid in ids:
        dd = client_data_dir(cid, cwd)
        df = load_events_dataframe(dd)
        if df.empty:
            summary_rows.append(
                {
                    "Client": cid,
                    "Events": 0,
                    "Critical (open)": 0,
                    "High (open)": 0,
                    "Compliance %": None,
                    "Last event (UTC)": "—",
                }
            )
            continue

        df = df.copy()
        df["_res"] = df["resolved"].map(_row_resolved)
        open_mask = ~df["_res"]
        crit_o = int(((df["risk_level"] == "Critical") & open_mask).sum())
        high_o = int(((df["risk_level"] == "High") & open_mask).sum())
        pct = compliance_pct(df.drop(columns=["_res"], errors="ignore"))
        last_ts = str(df["ts"].max())[:19] if len(df) else "—"

        summary_rows.append(
            {
                "Client": cid,
                "Events": len(df),
                "Critical (open)": crit_o,
                "High (open)": high_o,
                "Compliance %": round(pct, 1) if pct is not None else None,
                "Last event (UTC)": last_ts,
            }
        )

        crit_df = df[(df["risk_level"] == "Critical") & open_mask].copy()
        if not crit_df.empty:
            crit_df.insert(0, "client_id", cid)
            crit_parts.append(crit_df.drop(columns=["_res"], errors="ignore"))

    summary = pd.DataFrame(summary_rows)
    if crit_parts:
        critical_open = pd.concat(crit_parts, ignore_index=True)
    else:
        critical_open = pd.DataFrame()

    return summary, critical_open
