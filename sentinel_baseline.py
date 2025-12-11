# sentinel_baseline.py
# --------------------
# Agent-side baseline collection and storage for Sentinel Guard.
#
# Responsibilities:
#   - Build a "baseline snapshot" of the system:
#       * Sysinfo (reuses existing collector)
#       * CPU/RAM stats over a sampling window
#       * Process list (name, exe path, user, parent, etc.)
#       * Network connections and listening ports
#       * Sensitive file state (for FIM) using user-specified paths
#   - Save the baseline as JSON on disk.
#   - Load the baseline on startup, so monitoring can compare against it later.
#
# Notes:
#   - This module does NOT do monitoring or alerting; that's Phase 3.
#   - It includes helpers to configure Windows auditing for FIM paths,
#     so that later we can look up "who changed what" via the Security log.

from __future__ import annotations

import json
import time
import statistics
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import psutil
import socket
from sentinel_sysinfo import get_system_info

# Where to store the baseline JSON file.
# For now we keep it next to this script as "sentinel_baseline.json".
BASELINE_FILE = Path(__file__).with_name("sentinel_baseline.json")

def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def _safe_process_info(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    """
    Safely extract basic info about a process.

    Returns:
        - dict with name, pid, exe path, user, cmdline, parent info
        - None if the process vanishes or we lack permissions.
    """
    try:
        with proc.oneshot():
            pid = proc.pid
            name = proc.name()
            exe = proc.exe() if proc.exe() else None
            username = proc.username() if proc.username() else None
            cmdline = proc.cmdline()
            ppid = proc.ppid()
            parent_name = None
            try:
                parent=proc.parent()
                if parent is not None:
                    parent_name=parent.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                parent_name=None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    return {
        'name': name,
        'pid': pid,
        'exe': exe,
        'username': username,
        'cmdline': cmdline,
        'ppid': ppid,
        'parent_name': parent_name,
    }

# ---------------------------------------------------------------------------
# Resource baseline (CPU / RAM)
# ---------------------------------------------------------------------------

def collect_resource_baseline(duration_seconds: int=10, interval_seconds: float = 1.0,) -> Dict[str, Any]:
    """
    Collect baseline CPU and RAM usage over a sampling window.

    We:
        - sample CPU and RAM every 'interval_seconds'
        - run this for ~duration_seconds
        - compute average, min, max, stddev, and sample count

    Returns a dict:
        {
            "sampling_window_seconds": ...,
            "cpu": { "avg": ..., "max": ..., "min": ..., "stddev": ..., "sample_count": ... },
            "ram": { ...same keys... }
        }
    """
    cpu_samples: List[float] = []
    ram_samples: List[float] = []

    elapsed=0.0
    start_time=time.time()

    while elapsed < duration_seconds:
        # Blocking CPU sample for the interval.
        cpu=psutil.cpu_percent(interval=interval_seconds)
        # RAM usage percentage.
        ram = psutil.virtual_memory().percent

        cpu_samples.append(cpu)
        ram_samples.append(ram)

        elapsed=time.time()-start_time

    def _stats(samples: List[float]) -> Dict[str, Any]:
        """Compute simple stats for a list of numeric samples."""
        if not samples:
            return {
                'avg': 0.0,
                'max': 0.0,
                'min': 0.0,
                'stddev': 0.0,
                'sample_count': 0,
            }
        return {
            'avg': float(statistics.fmean(samples)),
            'max': float(max(samples)),
            'min': float(min(samples)),
            'stddev': float(statistics.stdev(samples)) if len(samples) > 1 else 0.0,
            'sample_count': len(samples),
        }

    return {
        'sampling_window_seconds': duration_seconds,
        'cpu': _stats(cpu_samples),
        'ram': _stats(ram_samples),
    }

# ---------------------------------------------------------------------------
# Process baseline
# ---------------------------------------------------------------------------

def collect_process_baseline() -> List[Dict[str, Any]]:
    """
    Collect a baseline list of currently running processes.

    Returns:
        A list of dicts, one per process, with:
            - name
            - pid
            - exe
            - user
            - cmdline
            - ppid
            - parent_name
    """
    processes: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=None):
        info = _safe_process_info(proc)
        if info is not None:
            processes.append(info)

    return processes

# ---------------------------------------------------------------------------
# Network baseline
# ---------------------------------------------------------------------------

def collect_network_baseline() -> Dict[str, Any]:
    """
    Collect a snapshot of current network connections and listening ports.

    Returns:
        {
            "connections": [...],
            "listening_ports": [...]
        }

    Each record includes:
        - proto (tcp/udp)
        - local_ip, local_port
        - remote_ip, remote_port
        - status
        - process { name, pid, path, user }
    """
    connections: List[Dict[str, Any]] = []
    listening: List[Dict[str, Any]] = []

    # Cache pid -> process info so we don't query the same pid repeatedly.
    proc_cache: Dict[int, Dict[str, Any]] = {}

    def _get_proc_info_for_pid(pid:int) -> Optional[Dict[str, Any]]:
        """Return a small dict of process info for a given pid, or None."""
        if pid is None or pid <=0:
            return None
        if pid in proc_cache:
            return proc_cache[pid]
        try:
            proc=psutil.Process(pid)
            info=_safe_process_info(proc)
            if info is None:
                return None
            proc_cache[pid]={
                'name': info['name'],
                'pid': info['pid'],
                'path': info['exe'],
                'user': info['username'],
            }
            return proc_cache[pid]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    # "inet" covers TCP and UDP over IPv4/IPv6.
    for conn in psutil.net_connections(kind='inet'):
        laddr=conn.laddr if conn.laddr else None
        raddr=conn.raddr if conn.raddr else None

        local_ip=getattr(laddr, 'ip', None) if laddr else None
        local_port=getattr(laddr, 'port', None) if laddr else None
        remote_ip=getattr(raddr, 'ip', None) if raddr else None
        remote_port=getattr(raddr, 'port', None) if raddr else None

        proto='tcp' if conn.type == socket.SOCK_STREAM else 'udp'
        pid = conn.pid
        status = conn.status  # string like 'ESTABLISHED', 'LISTEN', etc.

        proc_info=_get_proc_info_for_pid(pid)

        record={
            'proto': proto,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'status': status,
            'process': proc_info,
        }

        if status == 'LISTEN':
            listening.append(record)
        else:
            connections.append(record)

    print(f"[NET] Baseline snapshot: {len(connections)} active, {len(listening)} listening")
    return {
        'connections': connections,
        'listening_ports': listening,
    }

# ---------------------------------------------------------------------------
# FIM baseline (sensitive files) + auditing setup
# ---------------------------------------------------------------------------

def _hash_file_sha256(path: Path) -> Optional[str]:
    """
    Compute the SHA-256 hash of a file or return None if it can't be read.
    """
    import hashlib

    if not path.is_file():
        return None
    try:
        h=hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def ensure_file_auditing(path: Path) -> bool:
    """
    Ensure that Windows auditing is enabled for the given file.

    Assumes:
        - Running on Windows as administrator.
        - Global "Object Access" auditing is already enabled (set by the user).

    We use PowerShell to:
        - get the current ACL for the file
        - add an AuditRule for Everyone for Write/Delete (Success+Failure)
        - set the updated ACL back on the file

    Returns:
        True if auditing appears to be configured successfully, False otherwise.
    """
    if not psutil.WINDOWS:
        # On non-Windows, we don't attempt to configure auditing.
        return False

    if not path.exists():
        print(f"[FIM] Path does not exist (skipping auditing config): {path}")
        return False

    ps_script = rf"""
$ErrorActionPreference = 'Stop'
$path = '{str(path)}'
$acl = Get-Acl -Path $path

# Create an AuditRule: monitor Write and Delete operations for Everyone.
$identity = 'Everyone'
$rights = [System.Security.AccessControl.FileSystemRights]::Write, 
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::Read
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$auditFlags = [System.Security.AccessControl.AuditFlags]::Success, `
            [System.Security.AccessControl.AuditFlags]::Failure

$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $identity, $rights, $inheritance, $propagation, $auditFlags
)

$acl.SetAuditRule($rule)
Set-Acl -Path $path -AclObject $acl
"""
    try:
        completed=subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_script],
            capture_output=True, check=True, text=True,
        )
    except OSError as e:
        print(f"[FIM] Failed to run PowerShell to set auditing for {path}: {e}")
        return False

    if completed.returncode != 0:
        print(f"[FIM] PowerShell auditing config failed for {path}")
        if completed.stdout.strip():
            print("      stdout:", completed.stdout.strip())
        if completed.stderr.strip():
            print("      stderr:", completed.stderr.strip())
        return False

    print(f"[FIM] Auditing configured for {path}")
    return True

def collect_sensitive_files_baseline(paths: List[Path]) -> Dict[str, Any]:
    """
    Collect baseline information for sensitive files, using the given paths.

    For each file, we record:
        - path
        - exists (True/False)
        - size_bytes (if accessible)
        - mtime (ISO string, if accessible)
        - sha256 (if we can read the file)
        - access: "ok" or "denied" (if we couldn't read/hash/stat properly)
    """
    items: List[Dict[str, Any]] = []

    for p in paths:
        record: Dict[str, Any] = {
            'path': str(p),
            'exists': False,
            'size_bytes': None,
            'mtime': None,
            'sha256': None,
            'access': 'unkown',
        }

        if not p.exists():
            record['exists'] = False
            record['access'] = 'missing'
            items.append(record)
            continue

        record['exists'] = True
        record['access'] = 'ok'

        try:
            stat=p.stat()
            record['size_bytes'] = stat.st_size
            mtime_dt=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            record['mtime'] = mtime_dt.isoformat()
        except (OSError, PermissionError):
            # Can't stat fully; mark as denied but keep "exists"
            record['access'] = 'denied'

        # Hash may fail if file is locked; that's okay.
        sha=_hash_file_sha256(p)
        if sha is None:
            # If hashing failed, reflect that in access if we haven't already.
            if record['access'] == 'ok':
                record['access'] = 'denied'
        record['sha256'] = sha

        items.append(record)
    return {'items': items}

def apply_fim_auditing_from_config(cfg: Dict[str, Any]) -> None:
    """
    Read 'fim_paths' from the agent config and ensure auditing is configured
    for each path (Windows only).

    This should be called:
        - on startup (if fim_paths exists), and
        - after any CONFIG_UPDATE that modifies fim_paths.
    """
    fim_paths = cfg.get('fim_paths', [])
    if not fim_paths:
        print('[FIM] No FIM paths configured')
        return

    print(f'[FIM] Ensuring Windows auditing is configured for FIM paths...')
    for p_str in fim_paths:
        p = Path(p_str)
        ensure_file_auditing(p)

# ---------------------------------------------------------------------------
# Full baseline collection + save/load
# ---------------------------------------------------------------------------
def collect_full_baseline(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect a full baseline snapshot using:
        - sysinfo
        - resource (CPU/RAM) stats
        - current process list
        - current network snapshot
        - sensitive file states for paths in cfg["fim_paths"]

    'cfg' is the agent configuration dict so we can include agent_id and display_name.
    """
    print("[*] Collecting full baseline snapshot...")

    # If fim_paths is configured, make sure auditing is configured (Windows).
    fim_paths_cfg = cfg.get("fim_paths") or []
    fim_path_objs = [Path(p) for p in fim_paths_cfg]

    if fim_path_objs:
        apply_fim_auditing_from_config(cfg)

    sysinfo = get_system_info()
    resources=collect_resource_baseline()
    processes=collect_process_baseline()
    network=collect_network_baseline()
    files=collect_sensitive_files_baseline(fim_path_objs)

    baseline: Dict[str, Any] = {
        'schema_version':1,
        'agent_id':cfg['agent_id'],
        'display_name':cfg['display_name'],
        'created_at':_now_iso(),
        'sysinfo':sysinfo,
        'resources':resources,
        'processes':processes,
        'network':network,
        'files':files,
    }

    print("[*] Baseline collection complete.")
    return baseline

def save_baseline(baseline: Dict[str, Any], path: Path = BASELINE_FILE) -> None:
    """
    Save the baseline dict to a JSON file on disk.
    """
    try:
        with path.open('w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2)
        print(f"[+] Baseline saved to {path}")
    except OSError as e:
        print(f"[!] Failed to save baseline: {e}")

def load_baseline(path: Path = BASELINE_FILE) -> Optional[Dict[str, Any]]:
    """
    Load the baseline from disk, if it exists.

    Returns:
        - dict if loaded successfully
        - None if file does not exist or can't be read/parsed
    """
    if not path.exists():
        return None

    try:
        with path.open('r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"[+] Loaded baseline from {path}")
        return data
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Failed to load baseline from {path}: {e}")
        return None
