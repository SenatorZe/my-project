"""
sentinel_alerts.py

Common helper functions and types for Sentinel alerts.

Phase 3 uses this module on BOTH:
    - the agent side (to create alerts), and
    - the controller side (to understand / display them).

Alerts are plain Python dicts that are JSON-serializable.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid


# ----------------------------
# Core helpers
# ----------------------------

def utc_now_iso() -> str:
    """
    Return current UTC time in ISO 8601 format.
    Example: '2025-12-16T15:02:42.123456Z'
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_alert_id(prefix: str) -> str:
    """
    Generate a unique alert ID string with a type prefix.
    Example: new_alert_id('fim') -> 'fim-3e5c4bba-...'
    """
    return f"{prefix}-{uuid.uuid4()}"


def _normalize_severity(severity: str) -> str:
    s = (severity or "").strip().lower()
    if s in ("low", "medium", "high"):
        return s
    return "low"


def _base_alert(
    *,
    alert_type: str,
    alert_id_prefix: str,
    agent_id: str,
    agent_display_name: Optional[str],
    severity: str,
    summary: str,
    reasons: List[str],
) -> Dict[str, Any]:
    """
    Create the shared core schema for ALL alerts.

    Canonical keys we want everywhere:
      - type
      - alert_type
      - alert_id
      - created_at
      - status
      - agent_id
      - agent_name
      - severity
      - summary
      - reasons

    Backwards-compat keys we also include:
      - agent_display_name (older network alerts used this)
    """
    agent_name = agent_display_name or agent_id

    return {
        "type": "alert",
        "alert_type": alert_type,
        "alert_id": new_alert_id(alert_id_prefix),
        "created_at": utc_now_iso(),
        "status": "NEW",

        "agent_id": agent_id,

        # canonical
        "agent_name": agent_name,

        # backwards compat (so older controller code / older alert builders don't break)
        "agent_display_name": agent_name,

        "severity": _normalize_severity(severity),
        "summary": summary or "",
        "reasons": reasons or [],
    }


# ----------------------------
# Process alerts
# ----------------------------

def make_process_alert(
    agent_id: str,
    agent_display_name: Optional[str],
    severity: str,
    summary: str,
    reasons: List[str],
    process_info: Dict[str, Any],
    baseline_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a standard 'process' alert dict.
    """
    alert = _base_alert(
        alert_type="process",
        alert_id_prefix="proc",
        agent_id=agent_id,
        agent_display_name=agent_display_name,
        severity=severity,
        summary=summary,
        reasons=reasons,
    )
    alert["process"] = process_info or {}
    alert["baseline"] = baseline_info or {}
    return alert


# ----------------------------
# Network alerts
# ----------------------------

def make_network_alert(
    agent_id: str,
    agent_display_name: Optional[str],
    severity: str,
    summary: str,
    reasons: List[str],
    connection: Dict[str, Any],
    process: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build a standard 'network' alert dict (now consistent with process alerts).
    """
    alert = _base_alert(
        alert_type="network",
        alert_id_prefix="net",
        agent_id=agent_id,
        agent_display_name=agent_display_name,
        severity=severity,
        summary=summary,
        reasons=reasons,
    )
    alert["connection"] = connection or {}
    alert["process"] = process or {}
    return alert


# ----------------------------
# FIM alerts
# ----------------------------

def make_fim_alert(
    agent_id: str,
    agent_display_name: Optional[str],
    severity: str,
    summary: str,
    reasons: List[str],
    *,
    path: str,
    event_type: str,          # CREATED | MODIFIED | DELETED
    before: Dict[str, Any],
    after: Dict[str, Any],
    attribution: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a standard 'fim' alert dict (consistent schema).
    Attribution can be added later (Phase 3C.6).
    """
    alert = _base_alert(
        alert_type="fim",
        alert_id_prefix="fim",
        agent_id=agent_id,
        agent_display_name=agent_display_name,
        severity=severity,
        summary=summary,
        reasons=reasons,
    )

    alert["path"] = path
    alert["event_type"] = (event_type or "").upper()
    alert["before"] = before or {}
    alert["after"] = after or {}
    alert["attribution"] = attribution or {
        "user": "unknown",
        "process": "unknown",
        "pid": None,
        "source": "none",
    }
    return alert
