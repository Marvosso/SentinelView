"""
SentinelView — Analysis module: risk thresholds and SecurityEvent emission.
"""

from __future__ import annotations

import csv
import hashlib
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable

from remediation import remediation_for
from settings_loader import AnalysisSettings, load_settings

ACCESS_REVIEW_COLUMNS = ("Employee_ID", "Access_Level", "Status")
PRIVACY_SCAN_COLUMNS = ("File_Path", "PII_Detected", "Risk_Score")

PII_TRUE = frozenset(
    {"1", "true", "yes", "y", "t", "pii", "detected", "present"}
)
PII_FALSE = frozenset({"0", "false", "no", "n", "f", "none", "clean", "absent"})


def _normalize_pii(value: str) -> bool | None:
    v = value.strip().lower()
    if v in PII_TRUE:
        return True
    if v in PII_FALSE:
        return False
    return None


def read_csv_dicts(path: Path) -> tuple[list[str], list[dict[str, str]], list[str]]:
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8-sig", newline="") as f:
            text = f.read()
    except OSError as e:
        return [], [], [f"Cannot read file: {e}"]

    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        return [], [], ["File has no header row."]

    fieldnames = [h.strip() if h else "" for h in reader.fieldnames]
    rows: list[dict[str, str]] = []
    try:
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})
    except csv.Error as e:
        return fieldnames, [], [f"CSV parse error: {e}"]

    return fieldnames, rows, errors


class RiskLevel(str, Enum):
    """Ordered severity for interpreted security events."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class SecurityEvent:
    """
    Central record for an interpreted security finding.
    timestamp is UTC; risk_level uses the four-tier model.
    """

    timestamp: datetime
    risk_level: RiskLevel
    summary: str
    detail: str
    source_log: str
    source_path: Path
    context: dict[str, str] = field(default_factory=dict)
    remediation: str = ""
    dedupe_key: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    resolved: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_path", Path(self.source_path))


def load_hr_roster(path: Path) -> set[str]:
    """
    Load authorized employee IDs from CSV.
    Expected header: Employee_ID (additional columns ignored).
    Returns empty set if file is missing or unreadable.
    """
    ids: set[str] = set()
    if not path.is_file():
        return ids
    try:
        with path.open(encoding="utf-8-sig", newline="") as f:
            text = f.read()
    except OSError:
        return ids
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return ids
    headers = [(h or "").strip() for h in reader.fieldnames]
    if "Employee_ID" not in headers:
        return ids
    for row in reader:
        eid = (row.get("Employee_ID") or "").strip()
        if eid:
            ids.add(eid)
    return ids


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_admin_access(row: dict[str, str]) -> bool:
    level = (row.get("Access_Level") or "").strip().casefold()
    return level == "admin"


def _pii_detected(row: dict[str, str]) -> bool:
    raw = (row.get("PII_Detected") or "").strip()
    v = raw.casefold()
    if v in PII_TRUE:
        return True
    return _normalize_pii(raw) is True


def _text_contains_keyword(haystack: str, keyword: str) -> bool:
    k = keyword.strip()
    if not k:
        return False
    return k.casefold() in haystack.casefold()


def _first_matching_pii_keyword(file_path: str, keywords: tuple[str, ...]) -> str | None:
    for kw in keywords:
        if _text_contains_keyword(file_path, kw):
            return kw.strip()
    return None


def _pii_effective(
    row: dict[str, str], file_path: str, settings: AnalysisSettings
) -> tuple[bool, str | None]:
    """
    PII signal from CSV column and/or configured keywords in File_Path.
    Returns (is_pii, matched_keyword_or_None).
    """
    if _pii_detected(row):
        return True, None
    mk = _first_matching_pii_keyword(file_path, settings.pii_keywords)
    if mk:
        return True, mk
    return False, None


def _first_matching_segment(
    file_path: str, segments: tuple[str, ...]
) -> str | None:
    pl = file_path.casefold()
    for seg in segments:
        s = seg.strip()
        if s and s.casefold() in pl:
            return seg.strip()
    return None


def dedupe_key_admin_off_roster(employee_id: str) -> str:
    """Stable key for off-roster Admin access (one alert per employee identity)."""
    key = employee_id.strip().casefold()
    return f"sv:v1:access:admin_not_on_roster:{key}"


def dedupe_key_privacy_pii_public(file_path: str) -> str:
    """Stable key for PII-in-Public-path finding (one alert per normalized path)."""
    norm = file_path.strip().casefold().replace("\\", "/")
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    return f"sv:v1:privacy:pii_public_path:{digest}"


def analyze_access_review_rows(
    rows: Iterable[dict[str, str]],
    hr_roster: set[str],
    source_path: Path,
) -> list[SecurityEvent]:
    """
    CRITICAL: Access_Level is Admin for an Employee_ID not on the HR roster.
    """
    events: list[SecurityEvent] = []
    roster_lower = {e.casefold() for e in hr_roster}

    for row in rows:
        if not _is_admin_access(row):
            continue
        eid = (row.get("Employee_ID") or "").strip()
        if not eid:
            continue
        if eid in hr_roster or eid.casefold() in roster_lower:
            continue
        ts = _utcnow()
        rl = RiskLevel.CRITICAL
        dk = dedupe_key_admin_off_roster(eid)
        events.append(
            SecurityEvent(
                timestamp=ts,
                risk_level=rl,
                summary="Admin access for employee not on HR roster",
                detail=(
                    f"Employee_ID {eid!r} has Access_Level Admin but is not listed "
                    f"on the HR roster."
                ),
                source_log="access_review",
                source_path=source_path,
                context={
                    "Employee_ID": eid,
                    "Access_Level": (row.get("Access_Level") or "").strip(),
                    "Status": (row.get("Status") or "").strip(),
                },
                remediation=remediation_for(rl.value, "access_review"),
                dedupe_key=dk,
            )
        )
    return events


def analyze_privacy_scan_rows(
    rows: Iterable[dict[str, str]],
    source_path: Path,
    settings: AnalysisSettings | None = None,
) -> list[SecurityEvent]:
    """
    PII-in-public exposure: severity comes from ``AnalysisSettings.pii_public_risk``
    (Medium / High / Critical), typically driven by ``settings.yaml`` plus optional
    ``client_policy.json`` alert sensitivity.
    """
    cfg = settings if settings is not None else load_settings(None)
    events: list[SecurityEvent] = []
    lvl = (cfg.pii_public_risk or "High").strip()
    if lvl == "Critical":
        default_rl = RiskLevel.CRITICAL
    elif lvl == "Medium":
        default_rl = RiskLevel.MEDIUM
    else:
        default_rl = RiskLevel.HIGH
    for row in rows:
        fp = (row.get("File_Path") or "").strip()
        if not fp:
            continue
        pii_ok, kw_hit = _pii_effective(row, fp, cfg)
        if not pii_ok:
            continue
        if _first_matching_segment(fp, cfg.secure_path_segments):
            continue
        pub_hit = _first_matching_segment(fp, cfg.public_path_segments)
        if not pub_hit:
            continue
        ts = _utcnow()
        rl = default_rl
        dk = dedupe_key_privacy_pii_public(fp)
        pii_src = (
            f"configured keyword {kw_hit!r} in path"
            if kw_hit
            else "PII_Detected column / standard PII signal"
        )
        detail = (
            f"File path {fp!r}: {pii_src}; exposure marker matched: {pub_hit!r} "
            f"(per settings.yaml public_path_segments)."
        )
        events.append(
            SecurityEvent(
                timestamp=ts,
                risk_level=rl,
                summary="PII signal in path with public/exposure segment (per policy)",
                detail=detail,
                source_log="privacy_scan",
                source_path=source_path,
                context={
                    "File_Path": fp,
                    "PII_Detected": (row.get("PII_Detected") or "").strip(),
                    "Risk_Score": (row.get("Risk_Score") or "").strip(),
                },
                remediation=remediation_for(rl.value, "privacy_scan"),
                dedupe_key=dk,
            )
        )
    return events


def analyze_ingested_csv(
    path: Path,
    log_type: str,
    hr_roster: set[str],
    settings_path: Path | None = None,
    *,
    data_dir: Path | None = None,
) -> list[SecurityEvent]:
    """Parse a validated log file and return security events from analysis rules."""
    from onboarding_policy import resolve_client_policy_path

    policy_path = resolve_client_policy_path(data_dir)
    settings = load_settings(settings_path, client_policy_path=policy_path)
    if log_type == "access_review":
        fieldnames, rows, errs = read_csv_dicts(path)
        if errs or tuple(fieldnames) != ACCESS_REVIEW_COLUMNS:
            return []
        return analyze_access_review_rows(rows, hr_roster, path)
    if log_type == "privacy_scan":
        fieldnames, rows, errs = read_csv_dicts(path)
        if errs or tuple(fieldnames) != PRIVACY_SCAN_COLUMNS:
            return []
        return analyze_privacy_scan_rows(rows, path, settings)
    return []


class SecurityEventStore:
    """Thread-safe in-memory store for SecurityEvent records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[SecurityEvent] = []

    def add_all(self, events: Iterable[SecurityEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def all_events(self) -> list[SecurityEvent]:
        with self._lock:
            return list(self._events)
