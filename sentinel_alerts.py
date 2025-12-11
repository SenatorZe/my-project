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

def utc_now_iso() -> str:
    """
    Return the current UTC time in ISO 8601 format.
    Example: '2025-11-30T18:22:11.123456Z'
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def new_alert_id(prefix: str) -> str:
    """
    Generate a unique-ish alert ID string with a type prefix.
    Example: new_alert_id('proc') -> 'proc-3e5c4bba-...'
    """
    return f"{prefix}-{uuid.uuid4()}"

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

        Fields:
            type        : 'alert'           (protocol top-level type)
            alert_type  : 'process'
            alert_id    : unique string
            agent_id    : which agent raised this
            agent_name  : friendly agent name (if known)
            created_at  : ISO8601 UTC timestamp
            severity    : 'low', 'medium', 'high'
            status      : initial alert status, always 'NEW' on creation
            summary     : short human-readable summary
            reasons     : list of machine-readable reason codes / messages
            process     : details about the process
            baseline    : optional baseline-related context
    """
    return {
        "type": "alert",
        "alert_type": "process",
        "alert_id": new_alert_id("proc"),
        "agent_id": agent_id,
        "agent_name": agent_display_name,
        "created_at": utc_now_iso(),
        "severity": severity,  # 'low' | 'medium' | 'high'
        "status": "NEW",  # controller will manage: NEW/OPEN/ACK/RESOLVED/DISMISSED/QUEUED
        "summary": summary,
        "reasons": reasons,
        "process": process_info,
        "baseline": baseline_info or {},
    }