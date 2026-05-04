"""
SentinelView — SQLite permanent store for security events (+ optional Supabase mirror).

Includes response tracking: acknowledge timestamps and resolution with remediation step
for closed-loop audit evidence.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analysis import RiskLevel, SecurityEvent

_lock = threading.Lock()

DEFAULT_DATA_DIR_NAME = "sentinelview_data"
DB_FILENAME = "sentinelview_events.sqlite"


def default_data_dir(cwd: Path | None = None) -> Path:
    root = cwd or Path.cwd()
    d = root / DEFAULT_DATA_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path(data_dir: Path | None = None) -> Path:
    base = data_dir if data_dir is not None else default_data_dir()
    base.mkdir(parents=True, exist_ok=True)
    return base / DB_FILENAME


def _migrate_response_columns(conn: sqlite3.Connection) -> None:
    cur = conn.execute("PRAGMA table_info(security_events)")
    colnames = {r[1] for r in cur.fetchall()}
    alters = [
        ("acknowledged", "INTEGER NOT NULL DEFAULT 0"),
        ("acknowledged_at", "TEXT"),
        ("resolved_at", "TEXT"),
        ("remediation_step_taken", "TEXT"),
        ("resolution_notes", "TEXT"),
    ]
    for col, decl in alters:
        if col not in colnames:
            conn.execute(f"ALTER TABLE security_events ADD COLUMN {col} {decl}")


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            source_log TEXT NOT NULL,
            source_path TEXT NOT NULL,
            context_json TEXT NOT NULL,
            remediation TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            dedupe_key TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TEXT,
            resolved_at TEXT,
            remediation_step_taken TEXT,
            resolution_notes TEXT
        )
        """
    )
    cur = conn.execute("PRAGMA table_info(security_events)")
    colnames = {r[1] for r in cur.fetchall()}
    if "dedupe_key" not in colnames:
        conn.execute("ALTER TABLE security_events ADD COLUMN dedupe_key TEXT")
    _migrate_response_columns(conn)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_security_events_dedupe_key "
        "ON security_events(dedupe_key)"
    )
    conn.commit()


def init_db(path: Path | None = None) -> Path:
    p = db_path(path)
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            _init_schema(conn)
        finally:
            conn.close()
    return p


def append_security_events(
    events: list[SecurityEvent],
    data_dir: Path | None = None,
) -> list[SecurityEvent]:
    """
    Persist new events. Returns only events actually inserted (duplicates skipped
    by dedupe_key).
    """
    if not events:
        return []
    p = init_db(data_dir)
    inserted: list[SecurityEvent] = []
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            conn.execute("BEGIN IMMEDIATE")
            for ev in events:
                dk = (ev.dedupe_key or "").strip() or f"sv:legacy:{ev.event_id}"
                dup = conn.execute(
                    "SELECT 1 FROM security_events WHERE dedupe_key = ? LIMIT 1",
                    (dk,),
                ).fetchone()
                if dup:
                    continue
                try:
                    conn.execute(
                        """
                        INSERT INTO security_events (
                            event_id, ts, risk_level, summary, detail, source_log,
                            source_path, context_json, remediation, resolved, dedupe_key,
                            acknowledged, acknowledged_at, resolved_at,
                            remediation_step_taken, resolution_notes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ev.event_id,
                            ev.timestamp.isoformat(),
                            ev.risk_level.value,
                            ev.summary,
                            ev.detail,
                            ev.source_log,
                            str(ev.source_path),
                            json.dumps(ev.context, ensure_ascii=False),
                            ev.remediation,
                            1 if ev.resolved else 0,
                            dk,
                            0,
                            None,
                            None,
                            None,
                            None,
                        ),
                    )
                except sqlite3.IntegrityError:
                    continue
                inserted.append(ev)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    if inserted:
        try:
            from supabase_backend import mirror_insert_events

            mirror_insert_events(inserted)
        except Exception:
            pass
    return inserted


def load_events_rows(data_dir: Path | None = None) -> list[dict[str, Any]]:
    p = db_path(data_dir)
    if not p.is_file():
        return []
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            _init_schema(conn)
            cur = conn.execute(
                """
                SELECT event_id, ts, risk_level, summary, detail, source_log,
                       source_path, context_json, remediation, resolved, dedupe_key,
                       acknowledged, acknowledged_at, resolved_at,
                       remediation_step_taken, resolution_notes
                FROM security_events
                ORDER BY ts DESC
                """
            )
            cols = [d[0] for d in cur.description]
            out: list[dict[str, Any]] = []
            for row in cur.fetchall():
                rec = dict(zip(cols, row))
                rec["resolved"] = bool(rec.get("resolved"))
                rec["acknowledged"] = bool(rec.get("acknowledged"))
                out.append(rec)
            return out
        finally:
            conn.close()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_acknowledged(event_id: str, data_dir: Path | None = None) -> None:
    """Record operator acknowledgement (response tracking)."""
    p = init_db(data_dir)
    now = _utc_iso()
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            conn.execute(
                """
                UPDATE security_events
                SET acknowledged = 1, acknowledged_at = ?
                WHERE event_id = ?
                """,
                (now, event_id),
            )
            conn.commit()
        finally:
            conn.close()
    try:
        from supabase_backend import mirror_event_update

        mirror_event_update(
            event_id,
            {
                "acknowledged": True,
                "acknowledged_at": now,
            },
        )
    except Exception:
        pass


def get_event_by_id(
    event_id: str, data_dir: Path | None = None
) -> dict[str, Any] | None:
    """Return one event row as dict, or None if missing."""
    p = db_path(data_dir)
    if not p.is_file():
        return None
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            _init_schema(conn)
            cur = conn.execute(
                """
                SELECT event_id, ts, risk_level, summary, detail, source_log,
                       source_path, context_json, remediation, resolved, dedupe_key,
                       acknowledged, acknowledged_at, resolved_at,
                       remediation_step_taken, resolution_notes
                FROM security_events
                WHERE event_id = ?
                """,
                (event_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cur.description]
            rec = dict(zip(cols, row))
            rec["resolved"] = bool(rec.get("resolved"))
            rec["acknowledged"] = bool(rec.get("acknowledged"))
            return rec
        finally:
            conn.close()


def set_resolution(
    event_id: str,
    *,
    remediation_step: str,
    resolution_notes: str,
    data_dir: Path | None = None,
    attested_by: str | None = None,
    attester_role: str | None = None,
) -> None:
    """
    Mark resolved and store which remediation step was performed (audit trail).

    After a successful write, generates a timestamped **Audit Evidence Package** Markdown
    file under ``<data_dir>/audit_evidence_packages/`` when optional attestation fields are
    stored only in that artifact (not duplicated in SQLite).

    Optional ``attested_by`` / ``attester_role`` populate the approval log in the evidence file.
    """
    p = init_db(data_dir)
    now = _utc_iso()
    notes = (resolution_notes or "").strip()
    step = (remediation_step or "").strip()
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            conn.execute(
                """
                UPDATE security_events SET
                    resolved = 1,
                    resolved_at = ?,
                    remediation_step_taken = ?,
                    resolution_notes = ?
                WHERE event_id = ?
                """,
                (now, step, notes, event_id),
            )
            conn.commit()
        finally:
            conn.close()
    try:
        from supabase_backend import mirror_event_update

        mirror_event_update(
            event_id,
            {
                "resolved": True,
                "resolved_at": now,
                "remediation_step_taken": step,
                "resolution_notes": notes,
            },
        )
    except Exception:
        pass

    try:
        from audit_evidence_package import write_resolved_event_evidence

        row = get_event_by_id(event_id, data_dir)
        store_dir = (
            Path(data_dir).resolve()
            if data_dir is not None
            else Path(p).parent.resolve()
        )
        if row and row.get("resolved"):
            write_resolved_event_evidence(
                row,
                store_dir,
                attested_by=attested_by,
                attester_role=attester_role,
            )
    except OSError:
        pass
    except Exception:
        pass


def set_resolved(event_id: str, resolved: bool, data_dir: Path | None = None) -> None:
    """Toggle resolved without step capture (legacy / quick clear)."""
    p = init_db(data_dir)
    with _lock:
        conn = sqlite3.connect(p, timeout=30)
        try:
            if resolved:
                conn.execute(
                    """
                    UPDATE security_events SET resolved = 1, resolved_at = ?
                    WHERE event_id = ?
                    """,
                    (_utc_iso(), event_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE security_events SET resolved = 0, resolved_at = NULL
                    WHERE event_id = ?
                    """,
                    (event_id,),
                )
            conn.commit()
        finally:
            conn.close()
    try:
        from supabase_backend import mirror_event_update

        if resolved:
            mirror_event_update(
                event_id, {"resolved": True, "resolved_at": _utc_iso()}
            )
        else:
            mirror_event_update(
                event_id,
                {
                    "resolved": False,
                    "resolved_at": None,
                },
            )
    except Exception:
        pass


def row_to_security_event(row: dict[str, Any]) -> SecurityEvent:
    ctx = json.loads(row["context_json"]) if row.get("context_json") else {}
    return SecurityEvent(
        timestamp=datetime.fromisoformat(row["ts"]),
        risk_level=RiskLevel(row["risk_level"]),
        summary=row["summary"],
        detail=row["detail"],
        source_log=row["source_log"],
        source_path=Path(row["source_path"]),
        context=ctx,
        remediation=row.get("remediation") or "",
        dedupe_key=str(row.get("dedupe_key") or ""),
        event_id=row["event_id"],
        resolved=bool(row.get("resolved")),
    )
