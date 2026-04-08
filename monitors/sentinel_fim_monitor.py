# sentinel_fim_monitor.py
# Phase 3C.3.1 — FIM detection module using standardized alert schema
# - Only monitors exact paths listed in cfg["fim_paths"]
# - Only runs if cfg["enable_fim"] is True
# - Compares against baseline["files"]["items"] (and tolerates other formats)
# - Emits CREATED / MODIFIED / DELETED
# - Returns standardized alert dicts via make_fim_alert(...)
# - Adds stable dedup_key for cooldown/dedup upstream

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.sentinel_alerts import make_fim_alert


def _safe_stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path)
    except Exception:
        return None


def _sha256_file(path: str) -> Optional[str]:
    """
    Returns sha256 hex digest for a file. Returns None if unreadable.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _mtime_iso_from_stat(st: os.stat_result) -> str:
    # Always store as UTC ISO string (matches your baseline example style)
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()


def _normalize_path(p: str) -> str:
    """
    Normalize paths for reliable matching between config + baseline.
    - On Windows, case-insensitive matching is common; normcase helps.
    - normpath collapses .. and slashes.
    """
    try:
        return os.path.normcase(os.path.normpath(p))
    except Exception:
        return p


def _extract_baseline_items(baseline: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Supports:
      baseline["files"]["items"] -> list of dicts  (your current JSON example)
      baseline["files"] -> list of dicts          (older/alternate shape)
      baseline missing -> []
    """
    if not isinstance(baseline, dict):
        return []

    files = baseline.get("files")
    if isinstance(files, dict):
        items = files.get("items")
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
        return []
    if isinstance(files, list):
        return [x for x in files if isinstance(x, dict)]

    return []


def _build_baseline_index(baseline: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Map normalized path -> baseline record dict
    """
    idx: Dict[str, Dict[str, Any]] = {}
    for item in _extract_baseline_items(baseline):
        p = item.get("path")
        if isinstance(p, str) and p.strip():
            idx[_normalize_path(p)] = item
    return idx


def _baseline_exists(rec: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(rec, dict):
        return False
    return bool(rec.get("exists", False))


def _baseline_size_bytes(rec: Optional[Dict[str, Any]]) -> Optional[int]:
    """
    Tolerate both 'size_bytes' (your JSON example) and 'size' (older code).
    """
    if not isinstance(rec, dict):
        return None
    val = rec.get("size_bytes", rec.get("size"))
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return None


def _baseline_mtime(rec: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(rec, dict):
        return None
    m = rec.get("mtime")
    return m if isinstance(m, str) else None


def _baseline_hash(rec: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(rec, dict):
        return None
    h = rec.get("sha256")
    return h if isinstance(h, str) and h else None


def _get_current_file_state(path: str) -> Dict[str, Any]:
    """
    Compute current file record.
    We always compute sha256 when the file exists (simple and reliable).
    (Later optimization: hash only when mtime/size changed.)
    """
    st = _safe_stat(path)
    if st is None:
        return {
            "path": path,
            "exists": False,
            "size_bytes": None,
            "mtime": None,
            "sha256": None,
            "access": "missing_or_no_access",
        }

    sha = _sha256_file(path)
    return {
        "path": path,
        "exists": True,
        "size_bytes": int(st.st_size),
        "mtime": _mtime_iso_from_stat(st),
        "sha256": sha,
        "access": "ok" if sha is not None else "hash_failed",
    }


def _event_type_for_change(before: Dict[str, Any], after: Dict[str, Any]) -> Optional[str]:
    """
    Returns one of: "CREATED" | "DELETED" | "MODIFIED" | None
    """
    before_exists = bool(before.get("exists", False))
    after_exists = bool(after.get("exists", False))

    if not before_exists and after_exists:
        return "CREATED"
    if before_exists and not after_exists:
        return "DELETED"
    if not before_exists and not after_exists:
        return None

    # both exist
    before_hash = before.get("sha256")
    after_hash = after.get("sha256")

    if isinstance(before_hash, str) and isinstance(after_hash, str):
        if before_hash != after_hash:
            return "MODIFIED"
        return None

    # fallback if hash not available
    if before.get("size_bytes") != after.get("size_bytes"):
        return "MODIFIED"
    if before.get("mtime") != after.get("mtime"):
        return "MODIFIED"

    return None


def detect_fim_changes(cfg: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Entry point (proc/net style):
      - returns list of standardized alert dicts
      - includes a stable dedup_key on each alert for cooldown/dedup upstream
    """
    if not isinstance(cfg, dict):
        return []

    if not cfg.get("enable_fim", False):
        return []

    paths = cfg.get("fim_paths", [])
    if not isinstance(paths, list) or not paths:
        return []

    baseline_idx = _build_baseline_index(baseline)

    # Agent identity (for schema consistency)
    agent_id = str(cfg.get("agent_id", "unknown-agent"))
    agent_name = cfg.get("display_name") or agent_id

    alerts: List[Dict[str, Any]] = []

    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue

        path = raw_path.strip()
        norm = _normalize_path(path)

        b_rec = baseline_idx.get(norm)

        before = {
            "path": path,
            "exists": _baseline_exists(b_rec),
            "size_bytes": _baseline_size_bytes(b_rec),
            "mtime": _baseline_mtime(b_rec),
            "sha256": _baseline_hash(b_rec),
            "access": (b_rec.get("access") if isinstance(b_rec, dict) else None),
        }

        after = _get_current_file_state(path)

        event_type = _event_type_for_change(before, after)
        if event_type is None:
            continue

        # Dedup key uses normalized path + event + "after hash" (or deleted / size+mtime fallback)
        after_hash = after.get("sha256")
        if event_type == "DELETED":
            key_tail = "deleted"
        elif isinstance(after_hash, str) and after_hash:
            key_tail = after_hash
        else:
            key_tail = f"{after.get('size_bytes')}|{after.get('mtime')}"

        dedup_key = f"fim|{norm}|{event_type}|{key_tail}"

        # A concise summary line (used in list view)
        # Keep it readable in the controller.
        summary = f"{event_type} {os.path.basename(path) or path}"

        # Reasons: give quick context without being verbose
        reasons: List[str] = []
        if event_type == "CREATED":
            reasons.append("File did not exist in baseline but exists now.")
        elif event_type == "DELETED":
            reasons.append("File existed in baseline but is missing now.")
        elif event_type == "MODIFIED":
            # prefer hash reason when possible
            if before.get("sha256") and after.get("sha256"):
                reasons.append("File hash changed from baseline.")
            else:
                reasons.append("File metadata changed from baseline (size/mtime).")

        alert = make_fim_alert(
            agent_id=agent_id,
            agent_display_name=agent_name,
            severity="medium",          # can tune later
            summary=summary,
            reasons=reasons,
            path=path,
            event_type=event_type,
            before=before,
            after=after,
            attribution=None,           # Phase 3C.6 will populate
        )

        # Attach dedup_key so agent can apply cooldown just like proc/net
        alert["dedup_key"] = dedup_key

        alerts.append(alert)

    return alerts
