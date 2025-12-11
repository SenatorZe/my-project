"""
sentinel_process_monitor.py

Phase 3A: logic for detecting suspicious processes by comparing the
current process list against the baseline and agent config.

This module does NOT talk to the network or controller directly.
It just:
    - scans current processes,
    - compares to baseline,
    - returns a list of alert dicts.

The agent code will call this periodically and then send any alerts
to the controller over the existing socket connection.
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional
from pathlib import Path

import psutil

from sentinel_alerts import make_process_alert

# Some simple "suspicious path" heuristics for Windows.
# We can refine this later.
SUSPICIOUS_DIR_KEYWORDS = [
    "\\appdata\\local\\temp",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\desktop\\",  # generic user dir (we'll refine later)
]

def _normalize_path(path: Optional[str]) -> Optional[str]:
    """
        Normalize a filesystem path for safer comparison:
            - convert to absolute if possible
            - lowercase
            - replace forward slashes with backslashes
    """
    if not path:
        return None
    try:
        p = Path(path)
        # On Windows, resolve() might raise if the path doesn't exist;
        # we ignore errors and just normalize the string.
        try:
            p = p.resolve()
        except OSError:
            pass
        return str(p).lower().replace("/", "\\").lower()
    except Exception:
        return str(path).replace("/", "\\").lower()

def _is_suspicious_path(exe: Optional[str]) -> bool:
    """
        Very basic heuristic for suspicious process paths on Windows.

        Examples:
            - executables running from user temp directories
            - unusual locations under user profiles or ProgramData

        This is not meant to be perfect, just a starting point for alerts.
    """
    if not exe:
        return False

    norm = _normalize_path(exe)
    if norm is None:
        return False

    # You can refine / tune this as you like.
    for kw in SUSPICIOUS_DIR_KEYWORDS:
        if kw.lower() in norm:
            return True

    return False

def _build_process_index_from_baseline(baseline: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
        Build a quick lookup from (name, path) -> baseline process info.

        Baseline is expected to have 'processes': [ {name, pid, path, user, ...}, ... ]

        We ignore PID for matching, because PIDs change all the time.
    """
    index: Dict[str, Dict[str, Any]] = {}

    processes = baseline.get("processes", [])
    for proc in processes:
        name = (proc.get("name") or "").lower()
        exe = _normalize_path(proc.get("exe"))
        key = f'{name}|{exe}'
        index[key] = proc

    return index

def _build_process_info(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    """
    Safely collect information about a psutil Process.
    """
    try:
        with proc.oneshot():
            name = proc.name()
            pid = proc.pid
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None

            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = None

            ppid = proc.ppid()
            parent_name = None
            try:
                parent=proc.parent()
                if parent is not None:
                    parent_name=parent.name()
            except (psutil.Error, AttributeError):
                parent_name=None

            cpu_percent = proc.cpu_percent(interval=None) # non-blocking, since we call this periodically

        return {
            'name': name,
            'pid': pid,
            'exe': exe,
            'user': username,
            'ppid': ppid,
            'parent_name': parent_name,
            'cpu_percent': cpu_percent,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def detect_suspicious_processes(
        cfg: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Main entrypoint: compare current processes against baseline and config.

    Returns:
        A list of *process alert dicts* (JSON-serializable) built with
        sentinel_alerts.make_process_alert().

    This function does NOT send anything to the controller; the agent
    will call this and then decide what to do with the returned alerts.
    """
    alerts: List[Dict[str, Any]] = []

    # If process monitoring is disabled in config, do nothing.
    if not cfg.get("enable_process_monitoring", True):
        return alerts

    # If we don't have a baseline yet, we can still optionally detect
    # obviously suspicious paths, but for now we'll simply do nothing.
    if not baseline:
        return alerts

    agent_id = cfg.get('agent_id', 'unknown-agent')
    agent_name = cfg.get('display_name') or agent_id

    # Build an index of 'known good' processes from the baseline.
    baseline_index = _build_process_index_from_baseline(baseline)

    # Threshold for "high CPU" relative to baseline.
    # For now we don't have per-process baseline CPU,
    # so we treat this as an absolute threshold in percent.
    cpu_spike_threshold = cfg.get("cpu_spike_percent_over_baseline", 80)

    try:
        current_procs = list(psutil.process_iter())
    except Exception:
        current_procs = []

    for p in current_procs:
        info = _build_process_info(p)
        if info is None:
            continue

        name = (info.get("name") or "").lower()
        exe = _normalize_path(info.get("exe"))
        key = f'{name}|{exe}'

        in_baseline = key in baseline_index
        suspicious_path = _is_suspicious_path(info.get("exe"))
        high_cpu = False

        cpu_percent = info.get("cpu_percent")
        if isinstance(cpu_percent, (int, float)):
            if cpu_percent >= cpu_spike_threshold:
                high_cpu=True

        reasons: List[str] = []

        if not in_baseline:
            reasons.append("process_not_in_baseline")

        if suspicious_path:
            reasons.append("suspicious_process_path")

        if high_cpu:
            reasons.append("high_cpu_usage")

        # For now, only raise an alert if there is at least one reason.
        if not reasons:
            continue

        # Build a human-readable one-line summary.
        summary_parts = [info.get("name") or "unknown.exe"]
        if 'process_not_in_baseline' in reasons:
            summary_parts.append("not in baseline")
        if 'suspicious_process_path' in reasons:
            summary_parts.append("weird path")
        if 'high_cpu_usage' in reasons:
            summary_parts.append(f"CPU ~{cpu_percent:.1f}%")
        summary = " | ".join(summary_parts)

        # Simple severity logic for now.
        if 'suspicious_process_path' in reasons or 'high_cpu_usage' in reasons:
            severity = "high"
        elif 'process_not_in_baseline' in reasons:
            severity = "medium"
        else:
            severity = "low"

        baseline_proc = baseline_index.get(key)

        alert = make_process_alert(
            agent_id=agent_id,
            agent_display_name=agent_name,
            severity=severity,
            summary=summary,
            reasons=reasons,
            process_info=info,
            baseline_info=baseline_proc,
        )

        alerts.append(alert)

    return alerts
