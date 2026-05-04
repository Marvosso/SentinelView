"""
Persist Client Onboarding Wizard step + draft until ``client_profile.json`` is saved.

Survives browser refresh via JSON under ``clients/<id>/onboarding_wizard_state.json``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from client_workspace import clients_root


def onboarding_wizard_state_path(client_id: str, cwd: Path | None = None) -> Path:
    return clients_root(cwd) / client_id / "onboarding_wizard_state.json"


def load_wizard_state(client_id: str, cwd: Path | None = None) -> dict[str, Any]:
    p = onboarding_wizard_state_path(client_id, cwd)
    if not p.is_file():
        return {"step": 0, "draft": {}, "mapping_animation_seen": False}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if "step" not in data:
            data["step"] = 0
        if "draft" not in data or not isinstance(data["draft"], dict):
            data["draft"] = {}
        if "mapping_animation_seen" not in data:
            data["mapping_animation_seen"] = False
        return data
    except (OSError, json.JSONDecodeError):
        return {"step": 0, "draft": {}, "mapping_animation_seen": False}


def save_wizard_state(
    client_id: str,
    *,
    step: int,
    draft: dict[str, Any],
    mapping_animation_seen: bool | None = None,
    cwd: Path | None = None,
) -> Path:
    """Write wizard progress (step + draft fields as plain dict)."""
    root = clients_root(cwd) / client_id
    root.mkdir(parents=True, exist_ok=True)
    prev = load_wizard_state(client_id, cwd)
    seen = (
        mapping_animation_seen
        if mapping_animation_seen is not None
        else prev.get("mapping_animation_seen", False)
    )
    doc = {
        "schema_version": 1,
        "step": max(0, min(3, int(step))),
        "draft": draft,
        "mapping_animation_seen": bool(seen),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path = onboarding_wizard_state_path(client_id, cwd)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def clear_wizard_state(client_id: str, cwd: Path | None = None) -> None:
    p = onboarding_wizard_state_path(client_id, cwd)
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass
