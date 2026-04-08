# sentinel_agent.py
# ------------------
# Main entry point for the Sentinel Agent.
#
# Current responsibilities:
#   - Load or create the agent configuration.
#   - Print a startup summary.
#   - Connect to the controller and send a "hello" message.
#   - wait for commands (PING, SYSINFO, etc.)
#   - Repeatedly try to connect to the controller.
# Later, this file will also:
#   - Run the monitoring engine and send alerts.
from pathlib import Path

from core.sentinel_baseline import (
collect_full_baseline, save_baseline,
load_baseline, apply_fim_auditing_from_config,
collect_sensitive_files_baseline,
)
from typing import Optional
from core.sentinel_protocol import send_message, recv_message
from core.sentinel_config import load_or_create_config, save_config
from core.sentinel_sysinfo import get_system_info
from monitors.sentinel_process_monitor import detect_suspicious_processes
from monitors.sentinel_network_monitor import detect_suspicious_connections
from training.train_network_model import load_network_model   # loads the saved Isolation Forest for network anomaly scoring
from training.train_process_model import load_process_model   # loads the saved Isolation Forest for process anomaly scoring
from monitors.sentinel_fim_monitor import detect_fim_changes
import sys
import socket
import time
import psutil
import shutil
import os
from datetime import datetime
import platform
import subprocess
import json

CURRENT_BASELINE: Optional[dict] = None
LAST_PROCESS_ALERT_TIMES: dict[str, float] = {}
LAST_NETWORK_ALERT_TIMES = {} # dedup_key -> last time (monotonic)

# Holds the trained Isolation Forest for network anomaly detection.
# Loaded once at startup from models/network_model.pkl.
# If the file doesn't exist yet (model hasn't been trained), this stays None
# and detect_suspicious_connections() falls back to rule-based detection.
NETWORK_MODEL = None

# Holds the trained Isolation Forest for process anomaly detection.
# Loaded once at startup from models/process_model.pkl.
# Falls back to rule-based detection if the file doesn't exist yet.
PROCESS_MODEL = None
LAST_FIM_ALERT_TIMES = {}
LAST_FIM_OBSERVED_STATE = {} # norm_path -> fingerprint string

def _run_cmd(cmd: list[str]) -> tuple[bool, str]:
    """
    Run a command safely and return (ok, combined_output).
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = (p.stdout or "") + (p.stderr or "")
        return (p.returncode == 0), out.strip()
    except Exception as e:
        return False, str(e)

def lockdown_file_admins_only(path: str) -> tuple[bool, dict]:
    """
    Remove all rights except SYSTEM + Administrators.
    Notes:
      - requires admin
      - uses takeown + icacls to force ownership and ACL reset
    """
    p = Path(path)
    if not p.exists():
        return False, {"message": f"File not found: {path}"}

    # 1) Take ownership (best-effort)
    _run_cmd(["takeown", "/F", str(p)])

    # 2) Remove inheritance + grant ONLY SYSTEM + Administrators
    ok1, out1 = _run_cmd(["icacls", str(p), "/inheritance:r"])
    ok2, out2 = _run_cmd(["icacls", str(p), "/grant:r", "SYSTEM:(F)", "Administrators:(F)"])

    ok = ok1 and ok2
    msg = "File locked down (SYSTEM + Administrators only)." if ok else "Failed to lock down file ACLs."

    return ok, {
        "message": msg,
        "path": str(p),
        "icacls_inheritance": out1,
        "icacls_grant": out2,
    }

def quarantine_file(path: str, quarantine_dir: str) -> tuple[bool, dict]:
    """
    Move the file into quarantine_dir (timestamped name), then lock it down.
    """
    src = Path(path)
    if not src.exists():
        return False, {"message": f"File not found: {path}"}

    qdir = Path(quarantine_dir)
    try:
        qdir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return False, {"message": f"Failed to create quarantine dir: {qdir} ({e})"}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = src.name.replace(":", "_")
    dst = qdir / f"{safe_name}.{ts}.quarantine"

    try:
        shutil.move(str(src), str(dst))
    except Exception as e:
        return False, {"message": f"Failed to move file to quarantine: {e}", "src": str(src), "dst": str(dst)}

    # After moving, lock it down
    ok_lock, lock_details = lockdown_file_admins_only(str(dst))
    if not ok_lock:
        return False, {
            "message": "Moved to quarantine but failed to lock down permissions.",
            "src": str(src),
            "dst": str(dst),
            "lockdown": lock_details,
        }

    return True, {
        "message": f"Quarantined + locked down: {dst}",
        "src": str(src),
        "dst": str(dst),
        "lockdown": lock_details,
    }

def _format_features(cfg: dict) -> str:
    """
    Build a short string describing which monitoring features are enabled.
    Used only for pretty startup output.
    """
    features = []
    if cfg.get('enable_process_monitor'):
        features.append("process")
    if cfg.get('enable_network_monitor'):
        features.append("network")
    if cfg.get('enable_fim'):
        features.append("fim")
    if cfg.get('enable_vulncheck'):
        features.append("vulncheck")

    if not features:
        return None
    return ", ".join(features)

def handle_command(message: dict, cfg: dict, sock: socket.socket) -> None:
    """
    Handle a single command message from the controller.

    For now, we only support:
        - PING -> respond with a command_result (pong-style).
        - SYSINFO -> collect system info and send it back.
        - BASELINE_CREATE
        (CONFIG_UPDATE for fim_paths will be added later)
    This function does NOT know or care about reconnects.
    It just reacts to whatever command it is given.
    """
    global CURRENT_BASELINE

    cmd = message.get('command')
    cmd_id = message.get('command_id')

    if cmd == 'PING':
        # Build a generic command_result for PING.
        result_msg={
            'type':'command_result',
            'command':'PING',
            'command_id':cmd_id,
            'status':'ok',
            'agent_id':cfg['agent_id'],
            'details':{
                'message':'pong'
            },
        }
        try:
            send_message(sock, result_msg)
            # Printing locally to see what is happening
            print(f'[<] Responded to Ping with command_result: (pong)')
        except Exception as e:
            print(f"[!] Failed to send command_result: {e}")
    elif cmd == 'SYSINFO':
        # Collect full system info and send it back in the 'details'
        try:
            sysinfo_data=get_system_info()
        except Exception as e:
            # If sysinfo collection fails, report an error.
            error_msg={
                'type':'command_result',
                'command':'SYSINFO',
                'command_id':cmd_id,
                'status':'error',
                'details':{
                    'message':f'Failed to collect system info: {e}'
                },
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
                print(f"[!] Sysinfo collection failed")
            return

        return_msg ={
            'type':'command_result',
            'command':'SYSINFO',
            'command_id':cmd_id,
            'status':'ok',
            'agent_id':cfg['agent_id'],
            'details': {
                # Full data goes here; controller can decide what to display
                'data':sysinfo_data
            },
        }
        try:
            send_message(sock, return_msg)
            print(f'[<] Sent SYSINFO data to controller')
        except Exception as e:
            print(f"[!] Failed to send SYSINFO result: {e}")
    elif cmd == 'BASELINE_CREATE':
        global CURRENT_BASELINE
        # Build or rebuild the baseline, save it, and send a summary back.
        try:
            baseline=collect_full_baseline(cfg)
            save_baseline(baseline)
            CURRENT_BASELINE=baseline
        except Exception as e:
            error_msg={
                'type':'command_result',
                'command':'BASELINE_CREATE',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{
                    'message':f'Failed to collect baseline: {e}'
                },
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
            print(f"[!] Baseline collection failed")
            return

        # Build a small summary for the controller to display.
        resources=baseline.get('resources', {})
        cpu=resources.get('cpu', {})
        ram=resources.get('ram', {})
        network=baseline.get('network', {}) # CHECK HERE TWIN
        files=baseline.get('files', {})

        summary={
            'created_at':baseline.get('created_at'),
            'process_count':len(baseline.get('processes', [])),
            'cpu_avg': cpu.get('avg'),
            'cpu_max': cpu.get('max'),
            'ram_avg': ram.get('avg'),
            'network_connections': len(network.get('connections', [])),
            'listening_ports': len(network.get('listening_ports', [])),
            'fim_items': len(files.get('items', [])),
        }

        result_msg={
            'type':'command_result',
            'command':'BASELINE_CREATE',
            'command_id':cmd_id,
            'status':'ok',
            'agent_id':cfg['agent_id'],
            'details': {'summary':summary},
        }
        try:
            send_message(sock, result_msg)
            print("[<] Sent BASELINE_CREATE result to controller.")
        except Exception as e:
            print(f"[!] Failed to send BASELINE_CREATE result: {e}")
    elif cmd == 'CONFIG_UPDATE':
        # Controller wants to update part of the agent's config
        # (fim_paths, enable_* flags, thresholds).
        params = message.get('params') or {}

        updated_keys = []
        error_message = None

        # -------- FIM paths --------
        if 'fim_paths' in params:
            raw_paths = params.get('fim_paths')

            if not isinstance(raw_paths, list) or not all(isinstance(p, str) for p in raw_paths):
                error_message = 'fim_paths must be a list of strings'
            else:
                existing = cfg.get('fim_paths') or []

                if raw_paths:
                    # APPEND mode: add new paths to existing, de-duplicate.
                    merged = existing + raw_paths
                    seen = set()
                    merged_unique = []
                    for p in merged:
                        if p not in seen:
                            seen.add(p)
                            merged_unique.append(p)
                    cfg['fim_paths'] = merged_unique
                    print('[CFG] Merged FIM paths (existing + new)')
                else:
                    # Empty list = clear all FIM paths.
                    cfg['fim_paths'] = []
                    print('[CFG] Cleared all FIM paths')

                updated_keys.append('fim_paths')

        # -------- Feature toggles (booleans) --------
        bool_fields = [
            'enable_process_monitor',
            'enable_network_monitor',
            'enable_fim',
            'enable_vulncheck',
        ]
        if error_message is None:
            for field in bool_fields:
                if field in params:
                    val = params.get(field)
                    if not isinstance(val, bool):
                        error_message = f'{field} must be a boolean (true/false)'
                        break
                    cfg[field] = val
                    updated_keys.append(field)

        # -------- Numeric thresholds --------
        num_fields = [
            'cpu_spike_percent_over_baseline',
            'ram_spike_percent_over_baseline',
        ]
        if error_message is None:
            for field in num_fields:
                if field in params:
                    val = params.get(field)
                    if not isinstance(val, (int, float)):
                        error_message = f'{field} must be a number.'
                        break
                    if val < 0 or val > 100:
                        error_message = f'{field} must be between 0 and 100.'
                        break
                    cfg[field] = int(val)
                    updated_keys.append(field)

        # -------- Final send/save logic --------
        if error_message is not None:
            result_msg = {
                'type': 'command_result',
                'command': 'CONFIG_UPDATE',
                'command_id': cmd_id,
                'status': 'error',
                'agent_id': cfg['agent_id'],
                'details': {'message': error_message},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f'[CFG] CONFIG_UPDATE error: {error_message}')
            return

        if updated_keys:
            save_config(cfg)
            apply_fim_auditing_from_config(cfg)
            print(f"[CFG] Updated config keys: {', '.join(updated_keys)}")

        result_msg = {
            'type': 'command_result',
            'command': 'CONFIG_UPDATE',
            'command_id': cmd_id,
            'status': 'ok',
            'agent_id': cfg['agent_id'],
            'details': {
                'updated_keys': updated_keys,
            },
        }
        try:
            send_message(sock, result_msg)
            print(f"[<] Sent CONFIG_UPDATE result to controller.")
        except Exception as e:
            print(f"[!] Failed to send CONFIG_UPDATE result: {e}.")
    elif cmd == 'CONFIG_GET':
        # Return the current config to the controller.
        result_msg = {
            'type': 'command_result',
            'command': 'CONFIG_GET',
            'command_id': cmd_id,
            'status':'ok',
            'agent_id':cfg['agent_id'],
            'details':{
                # We send the whole config; controller decides what to show.
                'config':cfg
            },
        }
        try:
            send_message(sock, result_msg)
            print(f"[<] Sent CONFIG_GET result to controller.")
        except Exception as e:
            print(f"[!] Failed to send CONFIG_GET result: {e}")

    elif cmd == 'BASELINE_GET':
        # Return a baseline summary if we have one.
        if CURRENT_BASELINE is None:
            result_msg = {
                'type': 'command_result',
                'command': 'BASELINE_GET',
                'command_id': cmd_id,
                'status': 'error',
                'agent_id': cfg['agent_id'],
                'details': {
                    'message': 'No baseline available yet.'
                },
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[BL] BASELINE_GET requested but no baseline is loaded.")
            return

        baseline = CURRENT_BASELINE

        resources=baseline.get('resources', {})
        cpu = resources.get('cpu', {})
        ram = resources.get('ram', {})
        network = baseline.get('network', {})
        files = baseline.get('files', {})

        summary={
            'created_at':baseline.get('created_at'),
            'process_count':len(baseline.get('processes', [])),
            'cpu_avg': cpu.get('avg'),
            'cpu_max': cpu.get('max'),
            'ram_avg': ram.get('avg'),
            'network_connections': len(network.get('connections', [])),
            'listening_ports': len(network.get('listening_ports', [])),
            'fim_items': len(files.get('items', [])),
        }

        result_msg = {
            'type': 'command_result',
            'command': 'BASELINE_GET',
            'command_id': cmd_id,
            'status': 'ok',
            'agent_id': cfg['agent_id'],
            'details': {'summary': summary},
        }
        try:
            send_message(sock, result_msg)
            print(f"[<] Sent BASELINE_GET result to controller.")
        except Exception as e:
            print(f"[!] Failed to send BASELINE_GET result: {e}")
    elif cmd == 'PROC_SCAN':
        """
        One-shot process scan for testing Phase 3A.

        The agent will:
                - ensure it has a baseline in memory (CURRENT_BASELINE),
                - run detect_suspicious_processes(cfg, baseline),
                - return the list of alerts (if any) to the controller.

        This does NOT start continuous monitoring; it's just a test hook.
        """
        # Make sure we have a baseline to compare against.
        # If CURRENT_BASELINE is None but a baseline file exists,
        # you likely have a load_baseline() helper; use it if available.
        # global CURRENT_BASELINE

        if CURRENT_BASELINE is None:
            try:
                CURRENT_BASELINE=load_baseline()
            except Exception as e:
                CURRENT_BASELINE=None
                print(f"[BL] Failed to load baseline for PROC_SCAN: {e}")

        if CURRENT_BASELINE is None:
            result_msg = {
                'type': 'command_result',
                'command': 'PROC_SCAN',
                'command_id': cmd_id,
                'status': 'error',
                'agent_id': cfg['agent_id'],
                'details': {
                    'message': 'No baseline available yet. Run BASELINE_CREATE first.'
                },
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[BL] PROC_SCAN requested but no baseline is loaded.")
            return

        baseline=CURRENT_BASELINE

        try:
            alerts=detect_suspicious_processes(cfg, baseline)
        except Exception as e:
            error_msg={
                'type':'command_result',
                'command':'PROC_SCAN',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{
                    'message':f'Error while scanning processes: {e}',
                },
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
            print(f"[BL] PROC_SCAN failed: {e}")
            return

        result_msg={
            'type':'command_result',
            'command':'PROC_SCAN',
            'command_id':cmd_id,
            'status':'ok',
            'agent_id':cfg['agent_id'],
            'details':{'alert_count':len(alerts), 'alerts':alerts},
        }
        try:
            send_message(sock, result_msg)
            print(f"[<] Sent PROC_SCAN result to controller with {len(alerts)} alerts.")
        except Exception as e:
            print(f"[!] Failed to send PROC_SCAN result: {e}")
    elif cmd =='KILL_PROCESS':
        params=message.get('params') or {}
        pid=params.get('pid')
        exe=params.get('exe')
        name=params.get('name')
        username=params.get('username')

        if pid is None:
            error_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':'Missing "pid" parameter for KILL_PROCESS.'},
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
            print(f"[KILL] KILL_PROCESS received without pid.")
            return

        try:
            pid_int=int(pid)
        except (TypeError, ValueError):
            error_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Invalid pid value: {pid!r}'},
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
            print(f"[KILL] KILL_PROCESS received with invalid pid: {pid!r}")
            return

        try:
            proc=psutil.Process(pid_int)
        except psutil.NoSuchProcess:
            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Process with PID {pid_int} does not exist.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] No such process: PID {pid_int}.")
            return
        except Exception as e:
            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Error finding process {pid_int}: {e}'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] Error finding process {pid_int}: {e}")
            return

        # Try to terminate gracefully first, then force kill if needed.
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            # --------------------------------------------------
            # 🔥 CLEAR COOLDOWN FOR THIS PROCESS
            # --------------------------------------------------
            # --- Cooldown reset: allow a re-alert if the same app is reopened ---
            try:
                global LAST_PROCESS_ALERT_TIMES
                proc_key = _process_alert_key({
                    "name": params.get("name"),
                    "exe": params.get("exe"),
                    "username": params.get("username"),
                })
                LAST_PROCESS_ALERT_TIMES.pop(proc_key, None)
            except Exception:
                # Never let cooldown cleanup break the kill action
                pass

            msg_text=f'Process {pid_int} terminated'
            if exe:
                msg_text+=f' (exe: {exe!r})'

            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'ok',
                'agent_id':cfg['agent_id'],
                'details':{'message':msg_text},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] {msg_text}")
        except psutil.NoSuchProcess:
            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Process {pid_int} does not exist (already existed).'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] Process {pid_int} already existed.")
        except psutil.AccessDenied:
            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Access denied when trying to kill process {pid_int}.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] Access denied for PID {pid_int}.")
        except Exception as e:
            result_msg={
                'type':'command_result',
                'command':'KILL_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Error killing process {pid_int}: {e}'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            print(f"[KILL] Error killing process {pid_int}: {e}")
    elif cmd == 'WHITELIST_PROCESS':
        """
        Add a process (name + exe + username) to the agent's process_whitelist
        in config, so future monitoring will ignore it.

        params:
            - name
            - exe
            - username
        """
        params=message.get('params') or {}
        w_name = params.get('name')
        w_exe = params.get('exe')
        w_user = params.get('username')

        if not w_name or not w_exe:
            error_msg={
                'type':'command_result',
                'command':'WHITELIST_PROCESS',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':'WHITELIST_PROCESS requires "name" and "exe".'},
            }
            try:
                send_message(sock, error_msg)
            except Exception:
                pass
            print(f"[WL] Missing name or exe in WHITELIST_PROCESS params.")
            return
        entry={
            'name':w_name,
            'exe':w_exe,
            'username':w_user,
        }
        # Merge into cfg["process_whitelist"], avoiding duplicates.
        wl = cfg.get("process_whitelist") or []
        # Avoid exact duplicates.
        already=False
        for existing in wl:
            if (existing.get('name') or '') == w_name and (existing.get('exe') or '') == w_exe and (existing.get('username') or '') == w_user:
                already=True
                break

        if not already:
            wl.append(entry)
            cfg["process_whitelist"]=wl
            try:
                save_config(cfg)
            except Exception as e:
                print(f'[WL] Failed to save config with new whitelist entry: {e}')

            # Optionally also add to baseline's process list if we have one
            if CURRENT_BASELINE is None:
                try:
                    procs=CURRENT_BASELINE.get('processes') or []
                    CURRENT_BASELINE['processes']=procs

                    #Building a similar dict shape as baseline uses.
                    baseline_entry={
                        'name':w_name,
                        'pid': None,
                        'exe':w_exe,
                        'username':w_user,
                        'cmdline':[],
                        'ppid': None,
                        'parent_name':None
                    }

                    # Avoid dup in baseline['processes'] as well
                    exists_in_baseline=False
                    for bp in procs:
                        if (
                                (bp.get("name") or "") == w_name
                                and (bp.get("exe") or "") == w_exe
                                and (bp.get("username") or "") == w_user
                        ):
                            exists_in_baseline=True
                            break

                    if not exists_in_baseline:
                        procs.append(baseline_entry)
                        try:
                            save_baseline(CURRENT_BASELINE)
                        except Exception as e:
                            print(f'[WL] Failed to save baseline after whitelist: {e}')
                except Exception as e:
                    print(f'[WL] Error updating baseline for WHITELIST_PROCESS: {e}')

            result_msg={
                'type':'command_result',
                'command':'WHITELIST_PROCESS',
                'command_id':cmd_id,
                'status':'ok',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Process "{w_name}" whitelisted for exe "{w_exe}".'},
            }
            try:
                send_message(sock, result_msg)
            except Exception as e:
                print(f"[WL] Failed to send WHITELIST_PROCESS result: {e}")
                pass
    elif cmd =='BLOCK_IP':
        params=message.get('params') or {}
        ip=(params.get('ip') or '').strip()

        if not ip:
            result_msg={
                'type':'command_result',
                'command':'BLOCK_IP',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':'Missing "ip" parameter.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        # Windows Firewall rule names
        rule_name_out=f'Sentinel Block OUT {ip}'
        rule_name_in=f'Sentinel Block IN {ip}'

        import subprocess

        try:
            # Block outbound traffic to that remote IP
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f'name={rule_name_out}', 'dir=out', 'action=block', f'remoteip={ip}'
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            # Block inbound traffic from that remote IP
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f'name={rule_name_in}', 'dir=in', 'action=block', f'remoteip={ip}'
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            # Record the block so we can show/unblock later
            blocked = cfg.get("blocked_ips") or []
            if ip not in blocked:
                blocked.append(ip)
                cfg["blocked_ips"] = blocked
                try:
                    save_config(cfg)
                except Exception:
                    pass

            result_msg={
                'type':'command_result',
                'command':'BLOCK_IP',
                'command_id':cmd_id,
                'status':'ok',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Blocked IP {ip} via Windows Firewall rules.'},
            }
        except Exception as e:
            result_msg={
                'type':'command_result',
                'command':'BLOCK_IP',
                'command_id':cmd_id,
                'status':'error',
                'agent_id':cfg['agent_id'],
                'details':{'message':f'Failed to block IP {ip}: {e}'},
            }
        blocked = cfg.get("blocked_ips") or []
        if ip not in blocked:
            blocked.append(ip)
            cfg["blocked_ips"] = blocked
            try:
                save_config(cfg)
            except Exception:
                pass

        try:
            send_message(sock, result_msg)
        except Exception:
            pass
    elif cmd == 'GET_BLOCKED_IPS':
        blocked = cfg.get("blocked_ips") or []

        result_msg = {
            "type": "command_result",
            "command": "GET_BLOCKED_IPS",
            "command_id": cmd_id,
            "status": "ok",
            "agent_id": cfg["agent_id"],
            "details": {"blocked_ips": blocked},
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
    elif cmd == 'UNBLOCK_IP':
        params = message.get("params") or {}
        ip = (params.get("ip") or "").strip()

        if not ip:
            result_msg = {
                "type": "command_result",
                "command": "UNBLOCK_IP",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": "Missing 'ip' parameter."},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        rule_name_out = f"Sentinel Block OUT {ip}"
        rule_name_in = f"Sentinel Block IN {ip}"

        import subprocess

        try:
            # Delete rules (if they don't exist, netsh may error — that's fine to treat as handled)
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"],
                check=False,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"],
                check=False,
                capture_output=True,
                text=True,
            )

            # Remove from our tracked list
            blocked = cfg.get("blocked_ips") or []
            cfg["blocked_ips"] = [x for x in blocked if x != ip]
            try:
                save_config(cfg)
            except Exception:
                pass

            result_msg = {
                "type": "command_result",
                "command": "UNBLOCK_IP",
                "command_id": cmd_id,
                "status": "ok",
                "agent_id": cfg["agent_id"],
                "details": {"message": f"Unblocked IP {ip} (removed Sentinel firewall rules)."},
            }

        except Exception as e:
            result_msg = {
                "type": "command_result",
                "command": "UNBLOCK_IP",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": f"Failed to unblock {ip}: {e}"},
            }

        try:
            send_message(sock, result_msg)
        except Exception:
            pass
    elif cmd == 'GET_IP_WHITELIST':
        wl = cfg.get('network_ip_whitelist') or []
        result_msg = {
            'type': 'command_result',
            'command': 'GET_IP_WHITELIST',
            'command_id': cmd_id,
            'status': 'ok',
            'agent_id': cfg['agent_id'],
            'details': {'network_ip_whitelist': wl},
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    elif cmd == 'ADD_IP_WHITELIST':
        params = message.get('params') or {}
        ip = (params.get('ip') or '').strip()
        if not ip:
            result_msg = {
                'type': 'command_result',
                'command': 'ADD_IP_WHITELIST',
                'command_id': cmd_id,
                'status': 'error',
                'agent_id': cfg['agent_id'],
                'details': {'message': 'Missing "ip" parameter.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return
        wl = cfg.get('network_ip_whitelist') or []
        if ip not in wl:
            wl.append(ip)
            cfg['network_ip_whitelist'] = wl
            try:
                save_config(cfg)
            except Exception:
                pass

        result_msg = {
            'type': 'command_result',
            'command': 'ADD_IP_WHITELIST',
            'command_id': cmd_id,
            'status': 'ok',
            'agent_id': cfg['agent_id'],
            'details': {'message': f'Whitelisted IP {ip}.', 'network_ip_whitelist': wl},
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    elif cmd == 'REMOVE_IP_WHITELIST':
        params = message.get('params') or {}
        ip = (params.get('ip') or '').strip()
        if not ip:
            result_msg = {
                'type': 'command_result',
                'command': 'REMOVE_IP_WHITELIST',
                'command_id': cmd_id,
                'status': 'error',
                'agent_id': cfg['agent_id'],
                'details': {'message': 'Missing "ip" parameter.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return
        wl = cfg.get("network_ip_whitelist") or []
        wl2 = [x for x in wl if x != ip]
        cfg["network_ip_whitelist"] = wl2
        try:
            save_config(cfg)
        except Exception:
            pass

        result_msg = {
            "type": "command_result",
            "command": "REMOVE_IP_WHITELIST",
            "command_id": cmd_id,
            "status": "ok",
            "agent_id": cfg["agent_id"],
            "details": {"message": f"Removed IP {ip} from whitelist.", "network_ip_whitelist": wl2},
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    elif cmd == 'CLEAR_IP_WHITELIST':
        cfg["network_ip_whitelist"] = []
        try:
            save_config(cfg)
        except Exception:
            pass

        result_msg = {
            "type": "command_result",
            "command": "CLEAR_IP_WHITELIST",
            "command_id": cmd_id,
            "status": "ok",
            "agent_id": cfg["agent_id"],
            "details": {"message": "Cleared IP whitelist.", "network_ip_whitelist": []},
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    elif cmd == "FIM_UPDATE_BASELINE_ITEM":
        """
        Accept a FIM change by updating ONE baseline file record.
        params:
          - path: string (exact file path to update in baseline['files']['items'])
        """
        params = message.get("params") or {}
        path = (params.get("path") or "").strip()

        if not path:
            result_msg = {
                "type": "command_result",
                "command": "FIM_UPDATE_BASELINE_ITEM",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": 'Missing "path" parameter.'},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        if CURRENT_BASELINE is None:
            result_msg = {
                "type": "command_result",
                "command": "FIM_UPDATE_BASELINE_ITEM",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": "No baseline loaded. Create a baseline first."},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        # Compute fresh baseline record for just this one path
        try:
            record_pack = collect_sensitive_files_baseline([Path(path)])
            items = record_pack.get("items") or []
            if not items:
                raise RuntimeError("Failed to compute file state for baseline update.")
            new_item = items[0]
        except Exception as e:
            result_msg = {
                "type": "command_result",
                "command": "FIM_UPDATE_BASELINE_ITEM",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": f"Failed to compute new baseline item: {e}"},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        # Ensure baseline structure exists
        files = CURRENT_BASELINE.get("files")
        if not isinstance(files, dict):
            files = {"items": []}
            CURRENT_BASELINE["files"] = files

        baseline_items = files.get("items")
        if not isinstance(baseline_items, list):
            baseline_items = []
            files["items"] = baseline_items

        # Update existing entry if present, else append
        # Use normcase/normpath to match Windows paths reliably
        import os
        target_norm = os.path.normcase(os.path.normpath(path))

        replaced = False
        for i, it in enumerate(baseline_items):
            if not isinstance(it, dict):
                continue
            p = it.get("path")
            if not isinstance(p, str):
                continue
            if os.path.normcase(os.path.normpath(p)) == target_norm:
                baseline_items[i] = new_item
                replaced = True
                break

        if not replaced:
            baseline_items.append(new_item)

        # Persist baseline to disk
        try:
            save_baseline(CURRENT_BASELINE)
        except Exception as e:
            result_msg = {
                "type": "command_result",
                "command": "FIM_UPDATE_BASELINE_ITEM",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": f"Updated in memory but failed to save baseline: {e}"},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        result_msg = {
            "type": "command_result",
            "command": "FIM_UPDATE_BASELINE_ITEM",
            "command_id": cmd_id,
            "status": "ok",
            "agent_id": cfg["agent_id"],
            "details": {
                "message": f"Baseline updated for: {path}",
                "item": new_item,
                "replaced": replaced,
            },
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    elif cmd == "FIM_LOCKDOWN_FILE":
        # params: { "path": "C:\\..." }
        params = message.get('params')
        path = (params.get("path") or "").strip()
        if not path:
            result_msg = {
                "type": "command_result",
                "command": "FIM_LOCKDOWN_FILE",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": "Missing path."},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        ok, details = lockdown_file_admins_only(path)
        result_msg = {
            "type": "command_result",
            "command": "FIM_LOCKDOWN_FILE",
            "command_id": cmd_id,
            "status": "ok" if ok else "error",
            "agent_id": cfg["agent_id"],
            "details": details,
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return

    elif cmd == "FIM_QUARANTINE_FILE":
        params = message.get('params')
        path = (params.get("path") or "").strip()
        if not path:
            result_msg = {
                "type": "command_result",
                "command": "FIM_QUARANTINE_FILE",
                "command_id": cmd_id,
                "status": "error",
                "agent_id": cfg["agent_id"],
                "details": {"message": "Missing path."},
            }
            try:
                send_message(sock, result_msg)
            except Exception:
                pass
            return

        quarantine_dir = cfg.get("fim_quarantine_dir") or r"C:\ProgramData\Sentinel\quarantine"
        ok, details = quarantine_file(path, quarantine_dir=quarantine_dir)
        result_msg = {
            "type": "command_result",
            "command": "FIM_QUARANTINE_FILE",
            "command_id": cmd_id,
            "status": "ok" if ok else "error",
            "agent_id": cfg["agent_id"],
            "details": details,
        }
        try:
            send_message(sock, result_msg)
        except Exception:
            pass
        return
    else:
        # For Future commands, we can add logic here to handle them.
        print(f"[!] Received unknown command: {cmd!r}")

def _normalize_exe_for_key(exe: str | None) -> str:
    """
    Normalize an exe path so the same file always maps to the same key:
        - lowercase
        - absolute if possible
        - backslashes
    """
    if not exe:
        return '?'

    try:
        p = Path(exe)
        try:
            p = p.resolve()
        except OSError:
            pass
        return str(p).replace('/', '\\').lower()
    except Exception:
        return str(exe).replace('/', '\\').lower()

def _process_alert_key(proc: dict) -> str:
    """
    Build a stable key for a process alert:
        name | exe | username

    So if the same executable under the same user keeps triggering,
    we treat it as the "same" thing for cooldown purposes, even if
    the PID changes.
    """
    name = (proc.get('name') or '').lower()
    exe = _normalize_exe_for_key(proc.get('exe'))
    user = (proc.get('username') or '').lower()
    return f"{name}|{exe}|{user}"

def get_windows_fim_attribution(path: str, lookback_seconds: int = 120) -> dict:
    """
    Improved attribution:
    - Uses Security 4663 events
    - Prefers WRITE/MODIFY/DELETE accesses over READ
    - Picks best-scoring event instead of first match
    """
    base = {"user": "unknown", "process": "unknown", "pid": None, "source": "none"}

    if not path or not isinstance(path, str):
        return base

    import platform
    if platform.system().lower() != "windows":
        return base

    import os, subprocess, json

    norm_target = os.path.normcase(os.path.normpath(path))

    # PowerShell returns recent 4663 events with useful fields:
    # ObjectName, ProcessName, ProcessId, SubjectUserName, SubjectDomainName, AccessMask, AccessList, TimeCreated
    ps = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddSeconds(-{int(lookback_seconds)})
$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4663; StartTime=$since}} -MaxEvents 300
$rows = foreach ($e in $events) {{
    $x = [xml]$e.ToXml()
    $data = @{{}}
    foreach ($d in $x.Event.EventData.Data) {{
        $n = $d.Name
        if ($n) {{ $data[$n] = [string]$d.'#text' }}
    }}
    [PSCustomObject]@{{
        TimeCreated  = [string]$e.TimeCreated
        ObjectName   = $data['ObjectName']
        SubjectUser  = $data['SubjectUserName']
        SubjectDomain= $data['SubjectDomainName']
        ProcessName  = $data['ProcessName']
        ProcessId    = $data['ProcessId']
        AccessMask   = $data['AccessMask']
        AccessList   = $data['AccessList']
    }}
}}
$rows | ConvertTo-Json -Depth 4
""".strip()

    try:
        cp = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=6,
        )
        out = (cp.stdout or "").strip()
        if not out:
            return base

        data = json.loads(out)
        rows = data if isinstance(data, list) else [data]

        # Noisy processes we want to down-rank (not hard-block)
        noisy = {
            "onedrive.exe",
            "searchindexer.exe",
            "everything.exe",
            "explorer.exe",  # sometimes touches metadata
            "python.exe",    # if your IDE runs helpers
            "pycharm64.exe",
            "pycharm.exe",
        }

        def parse_pid(pid_raw):
            if isinstance(pid_raw, str) and pid_raw:
                try:
                    return int(pid_raw, 0)  # handles 0x... and decimal
                except Exception:
                    return None
            return None

        def parse_mask(mask_raw):
            if isinstance(mask_raw, str) and mask_raw:
                try:
                    return int(mask_raw, 0)
                except Exception:
                    return None
            return None

        def is_write_like(access_mask: int | None, access_list: str | None) -> bool:
            # Common write-ish bits for files:
            # 0x2  = WriteData / AddFile
            # 0x4  = AppendData / AddSubdirectory
            # 0x10000 = DELETE (sometimes appears differently)
            # 0x40000 = WRITE_DAC etc (less relevant)
            if access_mask is not None:
                if (access_mask & 0x2) or (access_mask & 0x4) or (access_mask & 0x10000):
                    return True
            if isinstance(access_list, str):
                al = access_list.lower()
                if "writedata" in al or "appenddata" in al or "delete" in al or "write" in al:
                    return True
            return False

        best = None
        best_score = -10

        for r in rows:
            if not isinstance(r, dict):
                continue

            obj = r.get("ObjectName")
            if not isinstance(obj, str) or not obj:
                continue

            norm_obj = os.path.normcase(os.path.normpath(obj))
            if norm_obj != norm_target:
                continue

            proc = (r.get("ProcessName") or "").strip()
            proc_base = os.path.basename(proc).lower() if proc else ""

            dom = (r.get("SubjectDomain") or "").strip()
            usr = (r.get("SubjectUser") or "").strip()
            user = f"{dom}\\{usr}".strip("\\") if (dom or usr) else "unknown"

            access_mask = parse_mask(r.get("AccessMask"))
            access_list = r.get("AccessList")

            score = 0

            # Prefer write-like events heavily
            if is_write_like(access_mask, access_list):
                score += 50
            else:
                score += 5  # read-like, still possible but low confidence

            # Prefer non-SYSTEM actors
            if usr.upper() == "SYSTEM":
                score -= 20

            # Down-rank known noisy watchers/sync clients
            if proc_base in noisy:
                score -= 15

            # Prefer events where we have a user + process
            if user != "unknown":
                score += 5
            if proc:
                score += 5

            # Prefer more recent events: rows are usually newest-first, but we won’t assume
            # Add a small bump based on position if needed (handled naturally by scan order + score)

            if score > best_score:
                best_score = score
                best = r

        if not best:
            return base

        dom = (best.get("SubjectDomain") or "").strip()
        usr = (best.get("SubjectUser") or "").strip()
        user = f"{dom}\\{usr}".strip("\\") if (dom or usr) else "unknown"

        proc = (best.get("ProcessName") or "unknown").strip() or "unknown"
        pid = parse_pid(best.get("ProcessId"))

        # If best event was read-like, mark as low confidence (still returns something)
        access_mask = parse_mask(best.get("AccessMask"))
        access_list = best.get("AccessList")
        confidence = "high" if is_write_like(access_mask, access_list) else "low"

        return {
            "user": user or "unknown",
            "process": proc,
            "pid": pid,
            "source": f"security_4663_{confidence}",
        }

    except Exception:
        return base

def run_process_monitor_tick(cfg: dict, baseline: dict|None, sock: socket.socket)->None:
    """
    Run one 'tick' of the process monitoring logic:
        - compare current processes vs baseline
        - generate process alerts
        - send alerts to the controller, but with a cooldown so we don't
        spam the same alert on every tick.

    This is called periodically from inside _run_single_session().
    """
    print("[DEBUG] run_process_monitor_tick() called")#################################################################
    if not cfg.get('enable_process_monitor', True):
        return

    if baseline is None:
        # No baseline = nothing to compare against; we could log once if you like.
        # print("[PROC] Skipping process monitor tick: no baseline loaded.")
        return

    try:
        # Pass the trained model so ML scoring is used instead of the noisy
        # "not in baseline" rule. PROCESS_MODEL is None if the model hasn't
        # been trained yet — detect_suspicious_processes() handles that
        # gracefully by falling back to rule-based detection.
        alerts=detect_suspicious_processes(cfg, baseline, model=PROCESS_MODEL)
        print(f"[DEBUG] detect_suspicious_processes returned {len(alerts)} alerts")
    except Exception as e:
        print(f'[PROC] Error during process monitor tick: {e}')
        return

    if not alerts:
        return

    # Cooldown in seconds before we re-alert on the "same" process.
    cooldown=cfg.get('process_alert_cooldown_seconds', 300)
    if not isinstance(cooldown, (int, float)) or cooldown < 0:
        cooldown=300

    now=time.monotonic()

    global LAST_PROCESS_ALERT_TIMES

    for alert in alerts:
        proc=alert.get('process') or {}
        key=_process_alert_key(proc)

        last_time = LAST_PROCESS_ALERT_TIMES.get(key)

        if isinstance(last_time, (int, float)):
            try:
                if (now - last_time) < cooldown:
                    continue
            except TypeError:
                pass

        LAST_PROCESS_ALERT_TIMES[key] = now

        try:
            send_message(sock, alert)
            print(f"[PROC] Sent process alert to controller: {alert.get('summary', '')}")
        except Exception as e:
            print(f"[PROC] Failed to send process alert: {e}")
            # Don't break the entire tick for one failure; just move on.
            # But we *don't* roll back LAST_PROCESS_ALERT_TIMES for now.
            continue

    # Optional tiny cleanup: drop very old entries so the dict doesn't grow forever.
    # This is not critical for a school project, but it's easy:
    cutoff= now-(cooldown*4)
    cleaned: dict[str, float] = {}
    for k, t in LAST_PROCESS_ALERT_TIMES.items():
        if isinstance(t, (int, float)) and t >= cutoff:
            cleaned[k] = t
    LAST_PROCESS_ALERT_TIMES = cleaned

def run_network_monitor_tick(cfg:dict, baseline:dict|None, sock: socket.socket) -> None:
    print("[DEBUG] run_network_monitor_tick() called")
    if not cfg.get('enable_network_monitor', True):
        return
    if baseline is None:
        return

    # Pass the trained model in so detect_suspicious_connections() uses ML scoring.
    # NETWORK_MODEL is None if the model hasn't been trained yet — the function
    # handles that gracefully by falling back to rule-based detection.
    alerts = detect_suspicious_connections(cfg, baseline, model=NETWORK_MODEL)
    if not alerts:
        return

    cooldown = cfg.get('network_alert_cooldown_seconds', 300)
    if not isinstance(cooldown, (int, float)) or cooldown < 0:
        cooldown = 300

    now = time.monotonic()
    global LAST_NETWORK_ALERT_TIMES

    for alert in alerts:
        key=alert.get('dedup_key') or ''
        if not key:
            continue

        last = LAST_NETWORK_ALERT_TIMES.get(key)
        if isinstance(last, (int, float)) and (now-last) < cooldown:
            continue

        last=LAST_NETWORK_ALERT_TIMES[key]=now

        try:
            send_message(sock, alert)
            print(f'[NET] Sent network alert: {alert.get("summary", "")}')
        except Exception as e:
            print(f'[NET] Failed to send network alert: {e}')

        # Light cleanup
        cutoff = now - (cooldown * 4)
        LAST_NETWORK_ALERT_TIMES = {k: t for k, t in LAST_NETWORK_ALERT_TIMES.items()
                               if isinstance(t, (int, float)) and t >= cutoff}

def run_fim_monitor_tick(cfg: dict, baseline: dict | None, sock: socket.socket) -> None:
    """
    Run one tick of FIM:
          - checks only cfg["fim_paths"]
          - compares to baseline["files"]["items"]
          - sends CREATED/MODIFIED/DELETED alerts
          - enforces cooldown via dedup_key
          - edge-trigger suppression so we don't re-alert forever on same state
    """
    print("[DEBUG] run_fim_monitor_tick() called")
    if not cfg.get('enable_fim', True):
        return
    if baseline is None:
        return

    alerts = detect_fim_changes(cfg, baseline)
    if not alerts:
        return

    cooldown = cfg.get('fim_alert_cooldown_seconds', 30)
    if not isinstance(cooldown, (int, float)) or cooldown < 0:
        cooldown = 30

    now = time.monotonic()

    global LAST_FIM_ALERT_TIMES
    global LAST_FIM_OBSERVED_STATE  # <-- ADD THIS

    for alert in alerts:
        key = alert.get('dedup_key')
        if not isinstance(key, str) or not key:
            # fallback (shouldn't happen, but prevents crashes)
            key = f"fim|{alert.get('path')}|{alert.get('event_type')}"

        # ============================================================
        # EDGE-TRIGGER SUPPRESSION (prevents repeat alerts like your #2/#3)
        # If we've already alerted for the same resulting "after" state,
        # don't alert again even if cooldown expired.
        # ============================================================
        import os

        path = alert.get("path") or ""
        after = alert.get("after") or {}
        event_type = (alert.get("event_type") or "").upper()

        # normalize path for stable keying on Windows
        norm_path = os.path.normcase(os.path.normpath(path)) if isinstance(path, str) and path else str(path)

        # fingerprint the "after" state (what we're alerting about)
        after_hash = after.get("sha256")
        if isinstance(after_hash, str) and after_hash:
            fp = f"{event_type}|{after_hash}"
        else:
            fp = f"{event_type}|{after.get('exists')}|{after.get('size_bytes')}|{after.get('mtime')}"

        if LAST_FIM_OBSERVED_STATE.get(norm_path) == fp:
            continue  # already alerted on this exact state

        # record it now so we don't re-alert it later
        LAST_FIM_OBSERVED_STATE[norm_path] = fp
        # ============================================================

        last = LAST_FIM_ALERT_TIMES.get(key)
        if isinstance(last, (int, float)) and (now - last) < cooldown:
            continue

        LAST_FIM_ALERT_TIMES[key] = now

        try:
            # --- Phase 3C.6: Attribution enrichment (best effort) ---
            if cfg.get("fim_attribution_enabled", True):
                lookback = cfg.get("fim_attribution_lookback_seconds", 120)
                try:
                    lookback = int(lookback)
                except Exception:
                    lookback = 120

                try:
                    path = alert.get("path") or ""
                    if isinstance(path, str) and path:
                        alert["attribution"] = get_windows_fim_attribution(path, lookback_seconds=lookback)
                except Exception:
                    # Keep alert working even if attribution fails
                    pass

            send_message(sock, alert)
            print(f'[FIM] Sent FIM alert: {alert.get("event_type", "")} {alert.get("path", "")}')
        except Exception as e:
            print(f'[FIM] Failed to send FIM alert: {e}')

    # Light cleanup so dict doesn't grow forever
    cutoff = now - (cooldown * 4)
    LAST_FIM_ALERT_TIMES = {
        k: t for k, t in LAST_FIM_ALERT_TIMES.items()
        if isinstance(t, (int, float)) and t >= cutoff
    }

def _run_single_session(cfg: dict) -> None:
    """
    Executes a single session of connection and communication between the agent and
    a remote controller. The session involves establishing a connection, sending
    an initial hello message to introduce the agent, and continuously listening
    for commands from the controller.

    The method ensures graceful handling of connection errors, message receiving,
    and session cleanup. It supports reconnecting logic where future implementation
    can loop over multiple sessions.

    :param cfg: Configuration dictionary containing connection details, agent
        information, and its capabilities.
    :type cfg: dict
    :return: This method does not return a value.
    :rtype: None
    :raises KeyError: If required keys are missing in the provided configuration.
    :raises OSError: If there is a failure in socket connection or closure.
    :raises Exception: For any unexpected error during message transmission.
    """
    host = cfg['controller_host']
    port = cfg['controller_port']

    print(f"Connecting to controller at {host}:{port}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"[!] Failed to connect to controller: {e}")
        print('Exiting agent for now.')
        sock.close()
        return

    print('[+] Connected to controller.')
    # Build the hello message. This tells the controller:
    #   - who we are (agent_id, display_name)
    #   - what we can do (capabilities list)
    hello_msg={
        'type':'hello',
        'agent_id':cfg['agent_id'],
        'display_name':cfg['display_name'],
        'capabilities': _format_features(cfg)
    }

    try:
        # Send 'hello' over the socket.
        send_message(sock, hello_msg)
        print('[+] Sent hello message to controller.')
    except Exception as e:
        # If we can't even say hello, this session is useless.
        print(f"[!] Failed to send hello message: {e}")
        sock.close()
        return # Session ends; outer loop will retry later.

    # -------------------------------------------------------------
    # Process monitoring setup (Phase 3A)
    # -------------------------------------------------------------
    monitor_interval=cfg.get('monitor_interval_seconds', 60)
    if not isinstance(monitor_interval, (int, float)) or monitor_interval <= 0:
        monitor_interval=60

    last_monitor_time=time.monotonic()

    global CURRENT_BASELINE

    if CURRENT_BASELINE is None:
        try:
            CURRENT_BASELINE=load_baseline()
        except Exception as e:
            print(f"[BL] Could not load baseline on session start: {e}")

    try:
        # At this point, we consider the agent "connected".
        print('Agent is now connected and waiting for commands... (Ctrl + C to quit)')
        print(
            f"[DEBUG] In _run_single_session, CURRENT_BASELINE is: {'set' if CURRENT_BASELINE is not None else 'None'}")#####################################################################

        # MAIN RECEIVE LOOP for this session.
        while True:
            now=time.monotonic()
            # Blocking read:
            #   - returns a dict when a full message arrives
            #   - returns None if the connection is broken / closed8

            # --- Process monitoring tick (non-blocking) ---
            if now - last_monitor_time >= monitor_interval:
                run_process_monitor_tick(cfg, CURRENT_BASELINE, sock)
                run_network_monitor_tick(cfg, CURRENT_BASELINE, sock)
                run_fim_monitor_tick(cfg, CURRENT_BASELINE, sock)
                last_monitor_time=now
                # try:
                #     run_process_monitor_tick(cfg, CURRENT_BASELINE, sock)
                # except Exception as e:
                #     print(f"[PROC] Exception in monitor tick: {e}")
                # last_monitor_time=now

            try:
                msg = recv_message(sock, timeout=5)  # holds until message or real disconnect
            except Exception as e:
                print(f"[!] Error while receiving message: {e}")
                print("[!] Assuming controller is unavailable. Ending this session.")
                break

            if msg is None:
                # Either:
                #   - no data and timeout (controller silent), or
                #   - socket was closed / error.
                #
                # If the controller has gone away, future reads will keep
                # returning None or errors, so we treat this as a disconnect
                # and let the outer loop handle reconnect.
                # print("[!] No message received (timeout or connection closed).")
                # print("[!] Assuming controller is unavailable. Ending this session.")
                continue

            # At this point we have a valid JSON dict.
            msg_type = msg.get('type')
            if msg_type == 'command':
                # Let handle_command() decide what to do.
                handle_command(msg, cfg, sock)
            else:
                # Unknown or unexpected messages can be logged for now.
                print(f'[?] Received non-command message: {msg}')
    except KeyboardInterrupt:
        # Let KeyboardInterrupt bubble up so the outer loop can stop gracefully.
        print("\n[!] Agent interrupted by user, closing connection...")
        raise
    finally:
        # This always runs, even if there was an exception or break.
        try:
            sock.close()
        except OSError:
            pass
        print("[*] Agent socket closed.")

def run_agent_forever(cfg: dict) -> None:
    """
    High-level loop that keeps the agent running "forever".

    It does NOT itself maintain a connection.
    Instead, it repeatedly:
        - runs ONE connection session (_run_single_session),
        - waits for a configurable reconnect delay,
        - then tries again.

    This gives us automatic reconnect if:
        - the controller is offline at startup, or
        - the controller goes down while the agent is running.
    """
    recconect_delay=cfg.get('reconnect_interval_seconds', 5)

    print(f'Reconnect interval: {recconect_delay} seconds.')

    # This loop only stops when we get a KeyboardInterrupt (Ctrl+C).
    while True:
        try:
            # Try to run a single connection session.
            _run_single_session(cfg)
        except KeyboardInterrupt:
            # If Ctrl+C happens inside a session, we come here.
            print("\n[!] Agent interrupted by user, exiting...")
            break

        # If we reach here, _run_single_session() returned normally, which
        # means: connection failed or was lost. We now wait a bit and retry.
        print(f'[*] Reconnecting to controller in {recconect_delay} seconds...')
        try:
            time.sleep(recconect_delay)
        except KeyboardInterrupt:
            # User hit Ctrl+C during the sleep.
            print("\n[!] Agent interrupted during reconnect wait, exiting...")

            break

    print("[*] Agent main loop terminated.")

    # For now, we keep the connection open and just sleep.
    # In later phases, this is where we'll:
    #   - send alerts and monitoring data.
    # try:
    #     print("Agent is now idle but connected. (Ctrl+C to quit) )")
    #     while True:
    #         time.sleep(5)
    # except KeyboardInterrupt:
    #     print("\n[!] Agent interrupted by user, closing connection...")
    # finally:
    #     sock.close()
    #     print("[*] Agent socket closed.")

def main() -> int:
    """
    Entry point for the Sentinel Agent.

    Current responsibilities:
        - Load or create the agent configuration.
        - Print a concise startup summary.
        - Connect to the controller and send a hello message.

    Later, this function will:
        - Enter the main command & monitoring loop.
    """
    cfg = load_or_create_config()
    cfg.setdefault('blocked_ips', [])
    cfg.setdefault('network_ip_whitelist', [])
    try:
        save_config(cfg)
    except Exception:
        pass

    # Load baseline if it exists on disk.
    global CURRENT_BASELINE
    CURRENT_BASELINE=load_baseline()
    if CURRENT_BASELINE is None:
        print("[*] No existing baseline found. Use controller to create one.")
    else:
        print("[*] Baseline loaded in memory.")

    # Load the trained network anomaly model if one has been saved to disk.
    # This is created by running train_network_model.py after a baseline exists.
    # If the file isn't there yet, NETWORK_MODEL stays None and the network
    # monitor automatically falls back to rule-based detection — nothing breaks.
    global NETWORK_MODEL
    NETWORK_MODEL = load_network_model()
    if NETWORK_MODEL is not None:
        print("[*] Network anomaly model loaded.")
    else:
        print("[*] No network model found — network monitor will use rule-based fallback.")

    global PROCESS_MODEL
    PROCESS_MODEL = load_process_model()
    if PROCESS_MODEL is not None:
        print("[*] Process anomaly model loaded.")
    else:
        print("[*] No process model found — process monitor will use rule-based fallback.")

    # Ensure FIM auditing is configured for fim_paths (if any).
    apply_fim_auditing_from_config(cfg)

    agent_id=cfg['agent_id']
    display_name = cfg['display_name']
    controller_host = cfg['controller_host']
    controller_port = cfg['controller_port']
    reconnect_int = cfg['reconnect_interval_seconds']
    monitor_int = cfg['monitor_interval_seconds']
    features_str = _format_features(cfg)

    print("Sentinel Guard Agent")
    print("====================")
    print(f"Agent ID    : {agent_id}")
    print(f"Name        : {display_name}")
    print(f"Controller  : {controller_host}:{controller_port}")
    print(f"Reconnect   : every {reconnect_int}s if controller is down")
    print(f"Monitor run : every {monitor_int}s")
    print(f"Features    : {features_str}")
    print()

    # New behaviour: connect to the controller and send a hello message.
    # In the next steps, instead of exiting, we'll proceed to:
    #   - enter main loop
    # connect_and_hello(cfg)

    run_agent_forever(cfg)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())