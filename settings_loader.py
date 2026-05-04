"""
SentinelView — Load and save analysis settings from YAML.

Used by the Analysis module and the Streamlit Configuration tab.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AnalysisSettings:
    """Runtime analysis policy (PII keywords, public vs secure path interpretation)."""

    pii_keywords: tuple[str, ...]
    public_path_segments: tuple[str, ...]
    secure_path_segments: tuple[str, ...]
    # Severity for privacy_scan rule: PII signal + public path (unless secure path suppresses)
    pii_public_risk: str = "High"


def _norm_list(val: Any, *, default_if_missing: list[str] | None = None) -> tuple[str, ...]:
    if val is None:
        if default_if_missing is not None:
            return tuple(default_if_missing)
        return ()
    if isinstance(val, str):
        parts = [s.strip() for s in val.replace(",", "\n").splitlines() if s.strip()]
        return tuple(parts)
    if isinstance(val, (list, tuple)):
        out = [str(x).strip() for x in val if str(x).strip()]
        return tuple(out)
    return ()


def default_analysis_settings() -> AnalysisSettings:
    """When no file exists or keys are absent: public exposure defaults to 'public'."""
    return AnalysisSettings(
        pii_keywords=(),
        public_path_segments=("public",),
        secure_path_segments=(),
        pii_public_risk="High",
    )


def _merge_yaml_dict(data: dict[str, Any]) -> AnalysisSettings:
    pii = _norm_list(data.get("pii_keywords"), default_if_missing=None)
    if "public_path_segments" in data:
        pub = _norm_list(data.get("public_path_segments"), default_if_missing=None)
    else:
        pub = _norm_list(None, default_if_missing=["public"])
    sec = _norm_list(data.get("secure_path_segments"), default_if_missing=None)
    risk = str(data.get("pii_public_risk", "High")).strip()
    if risk not in ("Medium", "High", "Critical"):
        risk = "High"
    return AnalysisSettings(
        pii_keywords=pii,
        public_path_segments=pub,
        secure_path_segments=sec,
        pii_public_risk=risk,
    )


def merge_client_policy_dict(base: AnalysisSettings, policy: dict[str, Any]) -> AnalysisSettings:
    """Overlay ``client_policy.json`` onto YAML-derived settings."""
    alert = policy.get("alert_sensitivity")
    if not isinstance(alert, dict):
        alert = {}
    risk = str(alert.get("pii_in_public_path", base.pii_public_risk)).strip()
    if risk not in ("Medium", "High", "Critical"):
        risk = base.pii_public_risk
    extra = policy.get("derived_pii_keywords")
    if not isinstance(extra, list):
        extra = []
    extra_t = tuple(str(x).strip() for x in extra if str(x).strip())
    merged_kw = tuple(dict.fromkeys(tuple(base.pii_keywords) + extra_t))
    return replace(
        base,
        pii_keywords=merged_kw,
        pii_public_risk=risk,
    )


def load_settings(
    settings_path: Path | None = None,
    client_policy_path: Path | None = None,
) -> AnalysisSettings:
    """
    Load settings from YAML.

    If ``settings_path`` is set: use that file only when it exists; otherwise defaults
    (no fallback to cwd — avoids mixing explicit paths with implicit config).

    If ``settings_path`` is None: try ``SENTINELVIEW_SETTINGS`` then ``./settings.yaml``.
    """
    base: AnalysisSettings

    if settings_path is not None:
        if settings_path.is_file():
            try:
                raw = yaml.safe_load(settings_path.read_text(encoding="utf-8")) or {}
                if not isinstance(raw, dict):
                    base = default_analysis_settings()
                else:
                    base = _merge_yaml_dict(raw)
            except (OSError, yaml.YAMLError):
                base = default_analysis_settings()
        else:
            base = default_analysis_settings()
    else:
        base = _load_settings_implicit()

    if client_policy_path is not None and client_policy_path.is_file():
        try:
            raw_j = json.loads(client_policy_path.read_text(encoding="utf-8"))
            if isinstance(raw_j, dict):
                return merge_client_policy_dict(base, raw_j)
        except (OSError, json.JSONDecodeError):
            pass
    return base


def _load_settings_implicit() -> AnalysisSettings:
    env = os.environ.get("SENTINELVIEW_SETTINGS")
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                if isinstance(raw, dict):
                    return _merge_yaml_dict(raw)
            except (OSError, yaml.YAMLError):
                pass

    p = Path.cwd() / "settings.yaml"
    if p.is_file():
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(raw, dict):
                return _merge_yaml_dict(raw)
        except (OSError, yaml.YAMLError):
            pass

    return default_analysis_settings()


def analysis_settings_to_dict(settings: AnalysisSettings) -> dict[str, Any]:
    return {
        "pii_keywords": list(settings.pii_keywords),
        "public_path_segments": list(settings.public_path_segments),
        "secure_path_segments": list(settings.secure_path_segments),
        "pii_public_risk": settings.pii_public_risk,
    }


def save_settings(settings_path: Path, settings: AnalysisSettings) -> None:
    """Write settings to YAML (UTF-8). Creates parent directories if needed."""
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload = analysis_settings_to_dict(settings)
    text = yaml.safe_dump(
        payload,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
    header = (
        "# SentinelView — analysis configuration\n"
        "# pii_keywords: substrings matched in File_Path (case-insensitive).\n"
        "# public_path_segments: path markers treated as exposure (e.g. shared/public).\n"
        "# secure_path_segments: if matched, suppresses public+PII HIGH rule (vault areas).\n"
        "# pii_public_risk: Medium | High | Critical for privacy_scan PII-in-public rule "
        "(client_policy.json may override).\n\n"
    )
    settings_path.write_text(header + text, encoding="utf-8")


def settings_from_form_lines(
    pii_lines: str, public_lines: str, secure_lines: str
) -> AnalysisSettings:
    def split_nonempty(s: str) -> tuple[str, ...]:
        return tuple(line.strip() for line in s.splitlines() if line.strip())

    pii = split_nonempty(pii_lines)
    pub = split_nonempty(public_lines)
    sec = split_nonempty(secure_lines)
    if not pub:
        pub = ("public",)
    return AnalysisSettings(
        pii_keywords=pii,
        public_path_segments=pub,
        secure_path_segments=sec,
        pii_public_risk="High",
    )
