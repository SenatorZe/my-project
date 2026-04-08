# sentinel_process_monitor.py
# ---------------------------
# Detects suspicious processes by scoring them against an Isolation Forest
# model trained on the baseline process list.
#
# HOW THIS FILE CHANGED (ML integration):
#   BEFORE: Every process whose name+exe was not in the baseline fired an
#           alert. On a normal Windows machine this fires constantly:
#           app updates, new browser helpers, Python scripts, anything
#           installed after the baseline was taken.
#
#   AFTER:  We extract 12 numeric features from each process (exe location,
#           process name characteristics, parent process, CPU usage, etc.)
#           and ask the trained model whether the BEHAVIOUR looks anomalous.
#           A new app installed in Program Files launched by explorer.exe =
#           normal. A random-named exe from AppData Temp launched by
#           PowerShell = anomalous. The model makes that distinction.
#
# LAYERED DETECTION (same pattern as network monitor):
#   Layer 1 - Hard rules (always fire, no model needed):
#       - exe running from a Temp/Tmp folder          (suspicious_process_path)
#       - exe running from Downloads or Desktop        (suspicious_process_path)
#       - CPU usage above the configured threshold     (high_cpu_usage)
#
#   Layer 2 - ML model (Isolation Forest):
#       - Flags unusual COMBINATIONS of features that hard rules do not cover
#       - Falls back to the original rule-based logic if no model is loaded
#
# FALLBACK:
#   If models/process_model.pkl has not been created yet, detect_suspicious_processes()
#   uses the original rule set automatically — nothing breaks on first run.
from __future__ import annotations

from typing import Dict, Any, List, Optional
from pathlib import Path

import psutil
import numpy as np

from core.sentinel_alerts import make_process_alert

# Import ML helpers from the training module.
# _extract_process_features : converts one process dict into a numeric vector
# load_process_model        : loads the saved Isolation Forest from disk
from training.train_process_model import (
    _extract_process_features,
    load_process_model,
    SHELL_PROCESSES,
)

# ---------------------------------------------------------------------------
# HARD RULE: SUSPICIOUS DIRECTORY KEYWORDS
#
# Executables running from these locations are flagged regardless of the model.
# These rules are tight enough that they almost never produce false positives —
# legitimate software installed by a proper installer never runs from Temp or
# the user's Downloads folder persistently.
# ---------------------------------------------------------------------------
SUSPICIOUS_DIR_KEYWORDS = [
    "\\appdata\\local\\temp",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
]


def _normalize_path(path: Optional[str]) -> Optional[str]:
    """
    Normalise a filesystem path for safe string comparison:
        - lowercase
        - replace forward slashes with backslashes
        - attempt to resolve to absolute path

    Used so that "C:/Windows/system32/svchost.exe" and
    "c:\\windows\\system32\\svchost.exe" compare as equal.
    """
    if not path:
        return None
    try:
        p = Path(path)
        try:
            p = p.resolve()
        except OSError:
            pass
        return str(p).lower().replace("/", "\\")
    except Exception:
        return str(path).replace("/", "\\").lower()


def _is_suspicious_path(exe: Optional[str]) -> bool:
    """
    Hard rule: return True if the exe path contains a known suspicious
    directory keyword (Temp, Downloads, Desktop).

    This is kept as a hard rule — not delegated to ML — because it is
    a tight, high-confidence signal that rarely fires on legitimate software.
    """
    if not exe:
        return False
    norm = _normalize_path(exe)
    if norm is None:
        return False
    for kw in SUSPICIOUS_DIR_KEYWORDS:
        if kw.lower() in norm:
            return True
    return False


def _build_process_index_from_baseline(baseline: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Build a (name, exe) -> process dict lookup from the baseline process list.

    Used ONLY in fallback mode (when no model is available) to replicate
    the original 'process_not_in_baseline' rule.
    PIDs are intentionally ignored because they change on every boot.
    """
    index: Dict[str, Dict[str, Any]] = {}
    for proc in baseline.get("processes", []):
        name = (proc.get("name") or "").lower()
        exe  = _normalize_path(proc.get("exe"))
        key  = f'{name}|{exe}'
        index[key] = proc
    return index


def _build_process_info(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    """
    Safely collect info about a running process via psutil.

    Uses oneshot() so psutil only makes one system call to fetch all
    fields, which is faster than querying each field separately.

    Returns None if the process has already exited or access is denied.
    """
    try:
        with proc.oneshot():
            name = proc.name()
            pid  = proc.pid

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None

            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = None

            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                cmdline = None

            ppid        = proc.ppid()
            parent_name = None
            try:
                parent = proc.parent()
                if parent is not None:
                    parent_name = parent.name()
            except (psutil.Error, AttributeError):
                parent_name = None

            # Non-blocking CPU sample — uses the delta since the last call.
            # The agent calls this on every monitoring tick so the interval
            # is effectively the monitoring interval.
            cpu_percent = proc.cpu_percent(interval=None)

        return {
            'name':        name,
            'pid':         pid,
            'exe':         exe,
            'username':    username,
            'cmdline':     cmdline,
            'ppid':        ppid,
            'parent_name': parent_name,
            'cpu_percent': cpu_percent,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


# ---------------------------------------------------------------------------
# MAIN DETECTION FUNCTION
# ---------------------------------------------------------------------------

def detect_suspicious_processes(
        cfg: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None,
        model=None,   # trained IsolationForest from train_process_model.py, or None
) -> List[Dict[str, Any]]:
    """
    Scan all running processes and return alert dicts for anything suspicious.

    HOW ML SCORING WORKS (when model is provided):
        For each process we call _extract_process_features() to produce a
        12-number vector, then ask the model:

          model.predict()           -> +1 (normal) or -1 (anomaly)
          model.decision_function() -> float score:
                                         positive  = comfortably normal
                                         near zero = borderline
                                         negative  = anomalous
                                         very negative = highly suspicious

        Only processes where predict() == -1 get flagged by the ML layer.
        The score drives severity:
            score < -0.05 -> high
            score < 0     -> medium

    HARD RULES (always apply regardless of model):
        - exe from Temp/Tmp folder        -> proc_from_temp (high severity)
        - exe from Downloads/Desktop      -> suspicious_process_path (high)
        - CPU above configured threshold  -> high_cpu_usage

    FALLBACK (model=None):
        Uses the original rule-based approach:
          - process not in baseline -> alert
          - suspicious path         -> alert
          - high CPU                -> alert

    Parameters:
        cfg      - agent config dict
        baseline - baseline dict, or None
        model    - trained IsolationForest, or None for rule-based fallback
    """
    alerts: List[Dict[str, Any]] = []

    # Respect the kill-switch — return immediately if monitoring is disabled.
    if not cfg.get("enable_process_monitor", True):
        return alerts

    # ------------------------------------------------------------------
    # WHITELIST
    # Processes explicitly approved by the user via the controller.
    # These are skipped entirely — no ML, no hard rules.
    # ------------------------------------------------------------------
    whitelist_keys: set = set()
    for item in cfg.get("process_whitelist", []) or []:
        w_name = (item.get("name") or "").lower()
        w_exe  = _normalize_path(item.get("exe"))
        w_user = (item.get("username") or "").lower()
        whitelist_keys.add(f'{w_name}|{w_exe}|{w_user}')

    if not baseline:
        return alerts

    agent_id   = cfg.get('agent_id', 'unknown-agent')
    agent_name = cfg.get('display_name') or agent_id

    # CPU threshold — used by the hard rule (Layer 1).
    cpu_spike_threshold = cfg.get("cpu_spike_percent_over_baseline", 80)

    # Build baseline index for fallback mode only.
    baseline_index = _build_process_index_from_baseline(baseline) if model is None else {}

    try:
        current_procs = list(psutil.process_iter())
    except Exception:
        current_procs = []

    for p in current_procs:
        info = _build_process_info(p)
        if info is None:
            continue

        name = (info.get("name") or "").lower()
        exe  = _normalize_path(info.get("exe"))
        user = (info.get("username") or "").lower()

        # Skip whitelisted processes.
        whitelist_key = f'{name}|{exe}|{user}'
        if whitelist_key in whitelist_keys:
            continue

        reasons:  List[str] = []
        severity: str       = "medium"

        # ------------------------------------------------------------------
        # LAYER 1 — HARD RULES
        # These fire unconditionally regardless of whether a model is loaded.
        # ------------------------------------------------------------------

        # Hard rule A: exe running from a Temp or suspicious folder.
        # Legitimate installed software never runs persistently from Temp.
        if _is_suspicious_path(info.get("exe")):
            reasons.append("suspicious_process_path")
            severity = "high"

        # Hard rule B: abnormally high CPU usage.
        # The threshold comes from the agent config (default 80%).
        cpu_percent = info.get("cpu_percent")
        if isinstance(cpu_percent, (int, float)) and cpu_percent >= cpu_spike_threshold:
            reasons.append("high_cpu_usage")
            severity = "high"

        # ------------------------------------------------------------------
        # LAYER 2A — ML PATH (model is available)
        # Only runs if no hard rule already fired — we don't need to double-flag.
        # ------------------------------------------------------------------
        if model is not None and not reasons:
            features = _extract_process_features(info)
            X        = np.array(features, dtype=float).reshape(1, -1)
            label    = model.predict(X)[0]   # +1 = normal, -1 = anomaly

            if label == -1:
                score = model.decision_function(X)[0]

                # SCORE FLOOR: the Isolation Forest marks everything below the
                # contamination threshold as -1, which includes borderline cases
                # like score = -0.001. Those are not meaningful alerts — the
                # process is almost indistinguishable from normal.
                # We require score < -0.03 before raising an alert so that only
                # genuinely anomalous processes (well outside the normal cluster)
                # generate noise. This is the primary knob for reducing false
                # positives without sacrificing real detections.
                if score >= -0.03:
                    continue   # borderline — skip, don't alert

                reasons.append("ml_anomaly_detected")
                # Map the continuous score to a severity level.
                # More negative = further from the normal cluster = more suspicious.
                severity = "high" if score < -0.05 else "medium"

        # ------------------------------------------------------------------
        # LAYER 2B — FALLBACK (no model, use original rule-based logic)
        # ------------------------------------------------------------------
        elif model is None:
            baseline_key = f'{name}|{exe}'
            if baseline_key not in baseline_index:
                reasons.append("process_not_in_baseline")
                severity = "medium"

        # Nothing flagged this process — move on.
        if not reasons:
            continue

        # ------------------------------------------------------------------
        # BUILD ALERT
        # ------------------------------------------------------------------
        summary_parts = [info.get("name") or "unknown.exe"]
        if "suspicious_process_path" in reasons:
            summary_parts.append("suspicious path")
        if "high_cpu_usage" in reasons:
            summary_parts.append(f"CPU ~{cpu_percent:.1f}%")
        if "ml_anomaly_detected" in reasons:
            summary_parts.append("ML anomaly")
        if "process_not_in_baseline" in reasons:
            summary_parts.append("not in baseline")
        summary = " | ".join(summary_parts)

        baseline_proc = _build_process_index_from_baseline(baseline).get(
            f'{name}|{exe}'
        ) if baseline else None

        alert = make_process_alert(
            agent_id=agent_id,
            agent_display_name=agent_name,
            severity=severity,
            summary=summary,
            reasons=reasons,
            process_info=info,
            baseline_info=baseline_proc,
        )

        # Stable dedup key so the cooldown logic in the agent suppresses
        # repeated alerts for the same process across monitoring ticks.
        alert['dedup_key'] = f'{name}|{exe}|{user}'

        alerts.append(alert)

    return alerts
