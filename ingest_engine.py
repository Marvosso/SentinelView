"""
SentinelView — CSV data ingestion engine.
Watches a Windows directory for access_review.csv and privacy_scan.csv,
validates schema and row constraints, then confirms successful ingestion.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    print(
        "Missing dependency: install with  pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

from analysis import (
    ACCESS_REVIEW_COLUMNS,
    PII_FALSE,
    PII_TRUE,
    PRIVACY_SCAN_COLUMNS,
    SecurityEventStore,
    analyze_ingested_csv,
    load_hr_roster,
    read_csv_dicts,
)
from event_db import append_security_events

ACCESS_REVIEW_FILE = "access_review.csv"
PRIVACY_SCAN_FILE = "privacy_scan.csv"


def _normalize_pii(value: str) -> bool | None:
    v = value.strip().lower()
    if v in PII_TRUE:
        return True
    if v in PII_FALSE:
        return False
    return None


def _parse_risk_score(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def validate_access_review_rows(rows: Iterable[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    for i, row in enumerate(rows, start=2):
        eid = (row.get("Employee_ID") or "").strip()
        if not eid:
            errors.append(f"Row {i}: Employee_ID is empty.")
        al = (row.get("Access_Level") or "").strip()
        if not al:
            errors.append(f"Row {i}: Access_Level is empty.")
        st = (row.get("Status") or "").strip()
        if not st:
            errors.append(f"Row {i}: Status is empty.")
    return errors


def validate_privacy_scan_rows(rows: Iterable[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    for i, row in enumerate(rows, start=2):
        fp = (row.get("File_Path") or "").strip()
        if not fp:
            errors.append(f"Row {i}: File_Path is empty.")
        pii_raw = (row.get("PII_Detected") or "").strip()
        if not pii_raw:
            errors.append(f"Row {i}: PII_Detected is empty.")
        elif _normalize_pii(pii_raw) is None:
            errors.append(
                f"Row {i}: PII_Detected must be a clear yes/no value (got {pii_raw!r})."
            )
        rs = _parse_risk_score(row.get("Risk_Score") or "")
        if rs is None:
            errors.append(f"Row {i}: Risk_Score must be a number (got {row.get('Risk_Score')!r}).")
        elif rs < 0:
            errors.append(f"Row {i}: Risk_Score must be non-negative (got {rs}).")
    return errors


def validate_access_review(path: Path) -> tuple[bool, list[str]]:
    fieldnames, rows, errs = read_csv_dicts(path)
    if errs:
        return False, errs
    if tuple(fieldnames) != ACCESS_REVIEW_COLUMNS:
        return False, [
            f"Invalid header. Expected columns {list(ACCESS_REVIEW_COLUMNS)}, "
            f"got {fieldnames}."
        ]
    row_errs = validate_access_review_rows(rows)
    if row_errs:
        return False, row_errs
    return True, []


def validate_privacy_scan(path: Path) -> tuple[bool, list[str]]:
    fieldnames, rows, errs = read_csv_dicts(path)
    if errs:
        return False, errs
    if tuple(fieldnames) != PRIVACY_SCAN_COLUMNS:
        return False, [
            f"Invalid header. Expected columns {list(PRIVACY_SCAN_COLUMNS)}, "
            f"got {fieldnames}."
        ]
    row_errs = validate_privacy_scan_rows(rows)
    if row_errs:
        return False, row_errs
    return True, []


def ingest_file(path: Path) -> tuple[bool, list[str]]:
    name = path.name.lower()
    if name == ACCESS_REVIEW_FILE:
        return validate_access_review(path)
    if name == PRIVACY_SCAN_FILE:
        return validate_privacy_scan(path)
    return False, [f"Unknown log type: {path.name}"]


def fingerprint(path: Path) -> tuple[float, int] | None:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


class IngestionHandler(FileSystemEventHandler):
    def __init__(
        self,
        watch_root: Path,
        on_ingested: Callable[[Path, str], None] | None = None,
        settle_seconds: float = 0.35,
        hr_roster: set[str] | None = None,
        event_store: SecurityEventStore | None = None,
        data_dir: Path | None = None,
        settings_path: Path | None = None,
    ) -> None:
        self.watch_root = watch_root.resolve()
        self._processed: dict[str, tuple[float, int]] = {}
        self._on_ingested = on_ingested
        self._settle_seconds = settle_seconds
        self._hr_roster = hr_roster if hr_roster is not None else set()
        self._event_store = event_store
        self._data_dir = data_dir
        self._settings_path = settings_path

    def _target_path(self, event: FileSystemEvent) -> Path | None:
        if event.is_directory:
            return None
        p = Path(event.src_path)
        if p.suffix.lower() != ".csv":
            return None
        low = p.name.lower()
        if low not in (ACCESS_REVIEW_FILE, PRIVACY_SCAN_FILE):
            return None
        try:
            resolved = p.resolve()
        except OSError:
            return None
        try:
            resolved.relative_to(self.watch_root)
        except ValueError:
            return None
        return resolved

    def dispatch(self, event: FileSystemEvent) -> None:
        if event.event_type not in ("created", "modified"):
            return
        path = self._target_path(event)
        if path is None:
            return
        time.sleep(self._settle_seconds)
        fp = fingerprint(path)
        if fp is None:
            return
        key = str(path)
        if self._processed.get(key) == fp:
            return
        ok, errors = ingest_file(path)
        if ok:
            self._processed[key] = fp
            log_type = (
                "access_review"
                if path.name.lower() == ACCESS_REVIEW_FILE
                else "privacy_scan"
            )
            msg = (
                f"[SentinelView] Ingestion OK: {log_type} — "
                f"{path.name} ({path}) successfully ingested and validated."
            )
            print(msg)
            events = analyze_ingested_csv(
                path,
                log_type,
                self._hr_roster,
                self._settings_path,
                data_dir=self._data_dir,
            )
            if self._data_dir is not None:
                inserted = (
                    append_security_events(list(events), self._data_dir) if events else []
                )
            else:
                inserted = list(events)
            if self._event_store is not None:
                self._event_store.add_all(inserted)
            if self._data_dir is not None and events and len(inserted) < len(events):
                print(
                    f"[SentinelView] Skipped {len(events) - len(inserted)} duplicate "
                    f"alert(s) already recorded (dedupe_key match in permanent store)."
                )
            for ev in inserted:
                print(
                    f"[SentinelView] SecurityEvent | {ev.risk_level.value} | "
                    f"{ev.summary} | {ev.timestamp.isoformat()} | {ev.detail} | "
                    f"Remediation: {ev.remediation}"
                )
            if self._on_ingested:
                self._on_ingested(path, log_type)
        else:
            print(
                f"[SentinelView] Ingestion FAILED: {path.name} — validation errors:",
                file=sys.stderr,
            )
            for e in errors:
                print(f"  - {e}", file=sys.stderr)


def _emit_analysis_for_sweep(
    path: Path,
    log_type: str,
    hr_roster: set[str],
    event_store: SecurityEventStore | None,
    data_dir: Path | None,
    settings_path: Path | None,
) -> None:
    events = analyze_ingested_csv(
        path, log_type, hr_roster, settings_path, data_dir=data_dir
    )
    if data_dir is not None:
        inserted = append_security_events(list(events), data_dir) if events else []
    else:
        inserted = list(events)
    if event_store is not None:
        event_store.add_all(inserted)
    if data_dir is not None and events and len(inserted) < len(events):
        print(
            f"[SentinelView] Skipped {len(events) - len(inserted)} duplicate "
            f"alert(s) already recorded (dedupe_key match in permanent store)."
        )
    for ev in inserted:
        print(
            f"[SentinelView] SecurityEvent | {ev.risk_level.value} | "
            f"{ev.summary} | {ev.timestamp.isoformat()} | {ev.detail} | "
            f"Remediation: {ev.remediation}"
        )


def sweep_existing(handler: IngestionHandler, watch_dir: Path) -> None:
    """Process log files already present before the watcher starts."""
    for name in (ACCESS_REVIEW_FILE, PRIVACY_SCAN_FILE):
        p = watch_dir / name
        if not p.is_file():
            continue
        fp = fingerprint(p)
        if fp is None:
            continue
        key = str(p.resolve())
        ok, errors = ingest_file(p)
        if ok:
            handler._processed[key] = fp
            log_type = (
                "access_review"
                if p.name.lower() == ACCESS_REVIEW_FILE
                else "privacy_scan"
            )
            print(
                f"[SentinelView] Ingestion OK: {log_type} — "
                f"{p.name} ({p}) successfully ingested and validated."
            )
            _emit_analysis_for_sweep(
                p,
                log_type,
                handler._hr_roster,
                handler._event_store,
                handler._data_dir,
                handler._settings_path,
            )
        else:
            print(
                f"[SentinelView] Startup sweep FAILED: {p.name}:",
                file=sys.stderr,
            )
            for e in errors:
                print(f"  - {e}", file=sys.stderr)


def run_watch(
    watch_dir: Path,
    hr_roster_path: Path | None = None,
    event_store: SecurityEventStore | None = None,
    data_dir: Path | None = None,
    settings_path: Path | None = None,
) -> None:
    watch_dir = watch_dir.resolve()
    watch_dir.mkdir(parents=True, exist_ok=True)
    persist_dir = (
        data_dir.resolve()
        if data_dir is not None
        else (watch_dir / "sentinelview_data").resolve()
    )
    persist_dir.mkdir(parents=True, exist_ok=True)
    roster_file = (
        hr_roster_path
        if hr_roster_path is not None
        else watch_dir / "hr_roster.csv"
    )
    hr_roster = load_hr_roster(roster_file)
    if not roster_file.is_file():
        print(
            f"[SentinelView] HR roster not found at {roster_file}; "
            "Admin-vs-roster checks use an empty roster.",
            file=sys.stderr,
        )
    handler = IngestionHandler(
        watch_dir,
        hr_roster=hr_roster,
        event_store=event_store,
        data_dir=persist_dir,
        settings_path=settings_path,
    )
    sweep_existing(handler, watch_dir)
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive=False)
    observer.start()
    print(
        f"[SentinelView] Watching {watch_dir} for "
        f"{ACCESS_REVIEW_FILE} and {PRIVACY_SCAN_FILE}. Press Ctrl+C to stop."
    )
    print(f"[SentinelView] Event database directory: {persist_dir}")
    if settings_path is not None:
        print(f"[SentinelView] Analysis settings file: {settings_path}")
    else:
        print(
            "[SentinelView] Analysis settings: auto "
            "(SENTINELVIEW_SETTINGS env or ./settings.yaml)"
        )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join(timeout=5)
    print("[SentinelView] Stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelView CSV ingestion engine (directory watch)."
    )
    parser.add_argument(
        "watch_dir",
        nargs="?",
        default=str(Path.cwd() / "ingest_inbox"),
        help="Directory to watch (default: ./ingest_inbox)",
    )
    parser.add_argument(
        "--hr-roster",
        dest="hr_roster",
        default=None,
        metavar="PATH",
        help="CSV with Employee_ID column (default: <watch_dir>/hr_roster.csv)",
    )
    parser.add_argument(
        "--data-dir",
        dest="data_dir",
        default=None,
        metavar="PATH",
        help="Where to store sentinelview_events.sqlite "
        "(default: <watch_dir>/sentinelview_data). "
        "Per-client: --data-dir clients/<id>/data with watch_dir clients/<id>/logs.",
    )
    parser.add_argument(
        "--settings",
        dest="settings",
        default=None,
        metavar="PATH",
        help="Analysis settings YAML (default: auto via cwd/settings.yaml when unset)",
    )
    args = parser.parse_args()
    hr_path = Path(args.hr_roster) if args.hr_roster else None
    ddir = Path(args.data_dir) if args.data_dir else None
    settings_arg = Path(args.settings) if args.settings else None
    event_store = SecurityEventStore()
    run_watch(
        Path(args.watch_dir),
        hr_roster_path=hr_path,
        event_store=event_store,
        data_dir=ddir,
        settings_path=settings_arg,
    )


if __name__ == "__main__":
    main()
