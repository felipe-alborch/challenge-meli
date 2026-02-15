from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_session_dir(session_id: str) -> Path:
    base = Path("runs") / session_id
    base.mkdir(parents=True, exist_ok=True)
    return base


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def log_agent_output(session_id: str, agent_name: str, payload: Dict[str, Any]) -> Path:
    """
    Guarda un JSON por agente en: runs/<session_id>/<agent_name>.json
    """
    session_dir = ensure_session_dir(session_id)
    out_path = session_dir / f"{agent_name}.json"

    envelope = {
        "timestamp_utc": utc_now_iso(),
        "session_id": session_id,
        "agent": agent_name,
        "payload": _to_jsonable(payload),
    }

    write_json(out_path, envelope)
    return out_path
