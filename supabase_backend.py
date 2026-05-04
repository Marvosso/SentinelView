"""
Optional Supabase mirror for SentinelView security_events.

Configure with environment variables:
  SUPABASE_URL          — project URL (https://....supabase.co)
  SUPABASE_SERVICE_KEY  — service role key (server-side; keep secret)
  SUPABASE_TABLE        — table name (default: security_events)

Create the table in Supabase (SQL):

  create table if not exists security_events (
    event_id text primary key,
    dedupe_key text unique,
    ts timestamptz not null,
    risk_level text not null,
    summary text not null,
    detail text not null,
    source_log text not null,
    source_path text not null,
    context_json jsonb not null,
    remediation text not null,
    resolved boolean not null default false,
    acknowledged boolean not null default false,
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    remediation_step_taken text,
    resolution_notes text
  );

  create unique index if not exists ux_security_events_dedupe_key
    on security_events (dedupe_key);
"""

from __future__ import annotations

import json
import os
from typing import Any

from analysis import SecurityEvent


def is_supabase_configured() -> bool:
    return bool(os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_SERVICE_KEY"))


def _table() -> str:
    return os.environ.get("SUPABASE_TABLE", "security_events")


def _event_row(ev: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": ev.event_id,
        "dedupe_key": ev.dedupe_key,
        "ts": ev.timestamp.isoformat(),
        "risk_level": ev.risk_level.value,
        "summary": ev.summary,
        "detail": ev.detail,
        "source_log": ev.source_log,
        "source_path": str(ev.source_path),
        "context_json": ev.context,
        "remediation": ev.remediation,
        "resolved": ev.resolved,
        "acknowledged": False,
        "acknowledged_at": None,
        "resolved_at": None,
        "remediation_step_taken": None,
        "resolution_notes": None,
    }


def mirror_insert_events(events: list[SecurityEvent]) -> None:
    """Insert events that were newly written to SQLite (no duplicate dedupe_key)."""
    if not events or not is_supabase_configured():
        return
    try:
        from supabase import create_client
    except ImportError:
        return

    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_KEY"]
    client = create_client(url, key)
    for ev in events:
        row = _event_row(ev)
        try:
            client.table(_table()).insert(row).execute()
        except Exception as exc:
            err = str(exc).lower()
            if "duplicate" in err or "23505" in err or "unique" in err:
                continue
            raise


def mirror_event_update(event_id: str, fields: dict[str, Any]) -> None:
    """Patch arbitrary columns on security_events (acknowledgement, resolution, etc.)."""
    if not is_supabase_configured() or not fields:
        return
    try:
        from supabase import create_client
    except ImportError:
        return

    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_KEY"]
    client = create_client(url, key)
    client.table(_table()).update(fields).eq("event_id", event_id).execute()


def mirror_resolved(event_id: str, resolved: bool) -> None:
    mirror_event_update(event_id, {"resolved": resolved})
