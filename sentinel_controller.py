# sentinel_controller.py
# -----------------------
# Main entry point for the Sentinel Controller.
# Phase 1 skeleton:
#   - Start a TCP server and listen for agent connections.
#   - Track connected agents (by address).
#   - Provide a minimal CLI: help, agents, quit.

import socket
import os
import platform
import time

import pyfiglet
import sys
import threading
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from datetime import datetime, timezone
from core.sentinel_protocol import recv_message,send_message
import json
import urllib.request
import urllib.parse
import re
import urllib.error
import hashlib

# Default sensitive paths we might suggest including for FIM.
DEFAULT_SENSITIVE_PATHS = [r'C:\Windows\System32\drivers\etc\hosts']

def _get_llm_api_url() -> str:
    return os.getenv("LLM_API_URL", "").strip()

def _get_llm_api_key() -> str:
    return os.getenv("LLM_API_KEY", "").strip()

def _get_llm_model(controller) -> str:
    return os.getenv("LLM_MODEL", "").strip()

def abuseipdb_check_ip(ip:str)-> tuple[bool, str, dict]:
    """
    Returns: (ok, message, data)
        ok=False means request failed.
        ok=True means request succeeded; message summarizes score.
    """
    api_key=os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return False, 'ABUSEIPDB_API_KEY not set in enviroment.', {}

    params = urllib.parse.urlencode({
        'ipAddress': ip,
        'maxAgeInDays': 90
    })

    url=f'https://api.abuseipdb.com/api/v2/check?{params}'

    req = urllib.request.Request(url)
    req.add_header('Key', api_key)
    req.add_header('Accept', 'application/json')

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw=resp.read().decode('utf-8', errors='replace')
            payload=json.loads(raw)
    except Exception as e:
        return False, f'AbuseIPDB request failed: {e}', {}

    data=payload.get('data') or {}
    score=data.get('abuseConfidenceScore', 0)
    reports=data.get('totalReports', 0)
    country=data.get('countryCode', 'N/A')

    msg=f'Score={score}, Reports={reports}, Country={country}'
    return True, msg, data

@dataclass
class AgentConnection:
    """
    Represents a single connected agent.
    Fields:
        - sock        : the socket connected to the agent.
        - addr        : remote address (ip, port).
        - agent_id    : unique ID reported by the agent in its hello message.
        - display_name: human-friendly name (usually hostname), also from hello.
    """
    sock: socket.socket
    addr: Tuple[str, int] # (IP, Port)
    agent_id: Optional[str] = None
    display_name: Optional[str] = None

    def label(self) -> str:
        """
        Human-friendly label for printing this agent in the CLI.
        Example: '192.168.1.50:54321'
        Priority:
            1. display_name + (agent_id)
            2. ip:port
        """
        ip, port =self.addr
        if self.display_name and self.agent_id:
            return f"{self.display_name} (id: {self.agent_id}) from {ip}:{port}"
        return f"{ip}:{port}"

class Controller:
    """
    Sentinel Guard Controller.

    This class owns:
        - the TCP listening socket
        - the list of connected agents
        - the background thread that accepts new connections
    Responsibilities (Phase 1 skeleton):
        - Listen on a TCP port for incoming agent connections.
        - Track connected agents.
        - Provide methods to list and clean up agents.
    The CLI (in main()) interacts with this class to:
        - start/stop the server
        - list agents
        - later: send commands, query status, etc.
    """

    def __init__(self, host: str='0.0.0.0', port: int=9000) -> None:
        # Network settings for the controller
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None # The TCP listening socket (created in start()).
        self._accept_thread: Optional[threading.Thread] = None # Background thread that runs _accept_loop().
        self._accepting = False # Flag used to tell the acceptance loop whether it should keep running.
        self._next_command_id = 1 # Simple counter to generate unique command IDs.

        # List of Currently connected agents.
        self.agents: List[AgentConnection] = []

        # A simple lock to protect self.agents when accessed from multiple threads.s
        self._agent_lock = threading.Lock()

        self.alerts: list[dict] = []
        self._next_alert_id:int = 1

        # -----------------------------------------
        # Groq LLM triage (controller-side)
        # -----------------------------------------
        self.llm_triage_enabled = True

        # Process alerts:
        # - suspicious => visible in main alerts list
        # - benign/unknown => hidden from main list, visible via `alerts --benign`
        self.llm_hide_benign_process_alerts = True

        # Cache to reduce API calls: key -> triage dict
        self.llm_triage_cache = {}

        # Which Groq model to use (newer recommended)
        self.groq_model = "llama-3.1-8b-instant"

        # How long we wait for Groq before giving up
        self.groq_timeout_seconds = 15

        # Only treat "suspicious" as a MAIN alert if confidence >= this threshold
        self.suspicious_confidence_threshold = 0.80

    def add_alert(self,alert:dict, agent: 'AgentConnection') -> int:
        """
        Store an alert received (or triggered) for a given agent.

        Wraps the raw alert dict with controller-specific metadata:
            - controller-level ID
            - agent label
            - status (NEW/OPEN/...)
        """
        if not alert.get('created_at'):
            alert['created_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        rec = {
            "id": self._next_alert_id,
            "agent_id": agent.agent_id,
            "agent_label": agent.label(),
            "status": alert.get("status", "NEW"),
            "raw": alert,

            "triage": None,
            "hidden": False,
        }
        self.alerts.append(rec)
        self._next_alert_id += 1
        return rec["id"]

    def next_command_id(self) -> str:
        """
        Generate a simple unique command ID for tracking commands
        and matching them to command_result messages.
        """
        cid=f'cmd-{self._next_command_id}'
        self._next_command_id += 1
        return cid

    def start(self) -> None:
        """
        Start the TCP server and begin accepting agent connections
        in a background thread.
        After this method returns:
            - The controller is listening on (host, port).
            - The CLI can keep running and use 'agents' to see new connections.
        """
        if self._server_sock is not None:
            print("[DEBUG] Controller.start() called but server is already running.")
            # Already started
            return

        try:
            print(f"[DEBUG] Starting controller on {self.host}:{self.port}")
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow quick restart after exit without waiting for TIME_WAIT.
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen()
        except OSError as e:
            print(f"Failed to start controller on {self.host}:{self.port} -> {e}")
            return

        print(f"[+] Controller listening on {self.host}:{self.port}")  # debug line
        self._server_sock = server_sock
        self._accepting = True

        # Start the accept loop in a seperate thread so the cli remains responsive
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name='ControllerAcceptThread',
            daemon=True
        )
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        """
        Background thread function that accepts incoming connections
        from agents and stores them in self.agents.
        This loop runs as long as self._accepting is True and the server
        socket is open. Each new connection is wrapped in an AgentConnection
        object and added to self.agents.
        For each new connection:
            - Accept the TCP connection.
            - Expect a 'hello' JSON message as the first message.
            - If the hello is valid, store agent_id and display_name.
            - If not, close the socket and ignore the connection.
        """
        assert self._server_sock is not None

        while self._accepting:
            try:
                # Block here until a new client connects.
                client_sock, addr = self._server_sock.accept()
            except OSError:
                # Socket closed or error during accept; stop the loop
                break

            ip, port = addr
            # Try to receive the hello message from the agent.
            hello = recv_message(client_sock)

            if not hello:
                # Either no message or bad JSON, or not a hello.
                print(f'[!] Connection from {ip}:{port} did not send a valid hello message. Closing.')
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            agent_id = hello.get('agent_id')
            display_name = hello.get('display_name')
            if not agent_id or not display_name:
                print(f"[!] Hello from {ip}:{port} missing agent_id or display_name. Closing.")
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            # Wrap the socket + address into our AgentConnection dataclass,
            # including the agent ID and display name reported by the agent.
            agent = AgentConnection(
                sock=client_sock,
                addr=addr,
                agent_id=agent_id,
                display_name=display_name,
            ) # Wrap the raw socket + address into our AgentConnection dataclass.

            # If an agent with the same agent_id already exists, remove it.
            with self._agent_lock: # Add the new agent to the list in a thread-safe way.
                old_agents = [a for a in self.agents if a.agent_id == agent_id]
                for old_agent in old_agents:
                    try:
                        old_agent.sock.close()
                    except OSError:
                        pass
                    try:
                        self.agents.remove(old_agent)
                    except ValueError:
                        pass
                self.agents.append(agent)

            ip, port = addr
            print(f'[+] Agent connected to {display_name} (id: {agent_id}) from {ip}:{port}.')

    def stop(self) -> None:
        """
        Stop accepting new connections and close all sockets.
        This is called when the program is shutting down (e.g. user types 'quit').
        It:
            - signals the accept loop to stop,
            - closes the listening socket,
            - closes all agent sockets,
            - waits briefly for the accept thread to finish.
        """
        self._accepting = False

        # Close the listening socket.
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        # Close all agent sockets.
        with self._agent_lock:
            for agent in self.agents:
                try:
                    agent.sock.close()
                except OSError:
                    pass
            self.agents.clear()

        # Wait for the accept thread to finish (ie if it exists)
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.0)
            self._accept_thread = None

    def list_agents(self) -> List[AgentConnection]:
        """
        Return a copy of the current list of connected agents.
        """
        with self._agent_lock:
            return list(self.agents)

    def remove_agents(self, agent: AgentConnection) -> None:
        """
        Remove an agent from the controller's list and close its socket.
        Safe to call multiple times.
        """
        with self._agent_lock:
            if agent in self.agents:
                self.agents.remove(agent)
        try:
            agent.sock.close()
        except OSError:
            pass

def print_agent_config(agent: AgentConnection, config: dict) -> None:
    """
    Nicely print the important bits of an agent's config.
    """
    controller_host = config.get('controller_host')
    controller_port = config.get('controller_port')
    enable_proc = config.get('enable_process_monitor')
    enable_net = config.get('enable_network_monitor')
    enable_fim = config.get('enable_fim')
    enable_vuln = config.get('enable_vulncheck')
    cpu_thr = config.get('cpu_spike_percent_over_baseline')
    ram_thr = config.get('ram_spike_percent_over_baseline')
    fim_paths = config.get('fim_paths') or []

    print(f"[CONFIG] {agent.label()}")
    print(f"  Controller   : {controller_host}:{controller_port}")
    print(f"  Monitor proc : {'enabled' if enable_proc else 'disabled'}")
    print(f"  Monitor net  : {'enabled' if enable_net else 'disabled'}")
    print(f"  Monitor FIM  : {'enabled' if enable_fim else 'disabled'}")
    print(f"  Vulncheck    : {'enabled' if enable_vuln else 'disabled'}")
    print()
    print("  CPU spike threshold : +{}% over baseline".format(cpu_thr if cpu_thr is not None else '?'))
    print("  RAM spike threshold : +{}% over baseline".format(ram_thr if ram_thr is not None else '?'))
    print()
    print("  FIM paths:")
    if not fim_paths:
        print("    (none)")
    else:
        for p in fim_paths:
            print(f"    - {p}")

def send_config_get_and_wait(controller: Controller, agent: AgentConnection, timeout: float = 30.0) -> None:
    """
    Ask the given agent for its config (CONFIG_GET) and print it.
    """
    if agent.agent_id is None:
        print("[!] Cannot send CONFIG_GET: agent_id is unknown.")
        return

    cmd_id = controller.next_command_id()

    cmd_msg = {
        'type': 'command',
        'command': 'CONFIG_GET',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent CONFIG_GET request to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send CONFIG_GET: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)

    if reply is None:
        print('[!] No response to CONFIG_GET (timeout or connection closed).')
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get("type") != "command_result":
        print(f"[?] Unexpected message type in response to CONFIG_GET: {reply}")
        return

    if reply.get('command_id') != cmd_id or reply.get('command') != 'CONFIG_GET':
        print(f"[?] Received command_result that does not match our CONFIG_GET: {reply}")
        return

    status = reply.get("status")
    details = reply.get("details") or {}
    config = details.get("config") or {}
    message=details.get("message","")

    if status != "ok":
        print(f"[!] CONFIG_GET error from {agent.label()}: {status} - {message}")
        return

    print_agent_config(agent, config)

# def print_process_alerts_from_proc_scan(agent: AgentConnection, alerts: list[dict]) -> None:
#     """
#     Pretty-print a list of process alerts returned by PROC_SCAN.
#     This is just for testing Phase 3A before we build the full alert UI.
#     """
#     if not alerts:
#         print(f'[PROC] No suspicious process reported by {agent.label()}.')
#         return
#
#     print(f'[PROC] {len(alerts)} suspicious process(es) reported by {agent.label()}:')
#
#     for i, alert in enumerate(alerts, start=1):
#         proc=alert.get('process') or {}
#         name=proc.get('name') or 'unknown.exe'
#         pid = proc.get("pid")
#         exe = proc.get("exe") or "?"
#         user = proc.get("username") or "?"
#         severity = alert.get("severity") or "?"
#         reasons = alert.get("reasons") or []
#         summary = alert.get("summary") or ""
#
#         print(f"  [{i}] {name} (PID {pid}, user: {user})")
#         print(f"      Path    : {exe}")
#         print(f"      Severity: {severity}")
#         if reasons:
#             print(f"      Reasons : {', '.join(reasons)}")
#         if summary:
#             print(f"      Summary : {summary}")
#         print()

def send_proc_scan_and_wait(controller: Controller, agent: AgentConnection, timeout: float=60.0) -> None:
    """
    Send a one-shot PROC_SCAN command to the agent and print the results.

    This uses the same command_result mechanism as SYSINFO / BASELINE_CREATE.
    """
    if agent.agent_id is None:
        print('[!] Cannot send PROC_SCAN: agent_id is unknown.')
        return

    cmd_id = controller.next_command_id()
    cmd_msg = {
        'type': 'command',
        'command': 'PROC_SCAN',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent PROC_SCAN to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send PROC_SCAN: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to PROC_SCAN (timeout or connection closed).')
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get("type") != "command_result":
        print(f"[?] Unexpected message type in response to PROC_SCAN: {reply}")

    if reply.get('command_id') != cmd_id or reply.get('command') != 'PROC_SCAN':
        print(f"[?] Received command_result that does not match our PROC_SCAN: {reply}")
        return

    status = reply.get("status")
    details = reply.get("details") or {}
    # alert_count = details.get("alert_count") or 0
    alerts = details.get("alerts") or []
    message=details.get("message","")

    if status != "ok":
        print(f"[!] PROC_SCAN error from {agent.label()}: {status} - {message}")
        return

    if not alerts:
        print(f'[PROC] No suspicious process reported by {agent.label()}.')
        return

    # Store alerts in the controller's alert list.
    for alert in alerts:
        # Ensure alert_type is set (our agent uses 'process' for these).
        if not alert.get("alert_type"):
            alert["alert_type"] = "process"
        controller.add_alert(alert, agent)

    print(f"[PROC] Stored {len(alerts)} process alert(s) from {agent.label()}.")
    print("       Use 'alerts' to list them, and 'alert N' to view details.")

    # print_process_alerts_from_proc_scan(agent, alerts)

def send_baseline_get_and_wait(controller: Controller, agent: AgentConnection, timeout: float=30.0) -> None:
    """
    Ask the given agent for its existing baseline summary (BASELINE_GET)
    without recomputing the baseline.
    """
    if agent.agent_id is None:
        print("[!] Cannot send BASELINE_GET: agent_id is unknown.")
        return

    cmd_id = controller.next_command_id()

    cmd_msg = {
        'type': 'command',
        'command': 'BASELINE_GET',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent BASELINE_GET request to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send BASELINE_GET: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to BASELINE_GET (timeout or connection closed).')
        print("   Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get("type") != "command_result":
        print(f"[?] Unexpected message type in response to BASELINE_GET: {reply}")
        return

    if reply.get('command_id') != cmd_id or reply.get('command') != 'BASELINE_GET':
        print(f"[?] Received command_result that does not match our BASELINE_GET: {reply}")
        return

    status = reply.get("status")
    details = reply.get("details") or {}
    summary = details.get("summary") or {}
    message=details.get("message","")

    if status != "ok":
        print(f"[!] BASELINE_GET error from {agent.label()}: {status} - {message}")
        return

    print_baseline_summary(agent, summary)

def print_baseline_summary(agent: AgentConnection, summary: dict) -> None:
    """
    Print a concise summary of a baseline creation result.
    """
    created_at = summary.get('created_at') or 'Unknown'
    process_count = summary.get('process_count', 0)
    cpu_avg = summary.get('cpu_avg')
    cpu_max = summary.get('cpu_max')
    ram_avg = summary.get('ram_avg')
    net_conns = summary.get('network_connections', 0)
    listening = summary.get('listening_ports', 0)
    fim_items = summary.get('fim_items', 0)

    print(f"[BASELINE] {agent.label()}")
    print(f"  Created   : {created_at}")
    print(f"  Processes : {process_count}")
    print(f"  CPU avg   : {cpu_avg}%  (max {cpu_max}%)")
    print(f"  RAM avg   : {ram_avg}%")
    print(f"  Net conns : {net_conns}")
    print(f"  Listening : {listening}")
    print(f"  FIM files : {fim_items}")

def send_baseline_create_and_wait(controller: Controller, agent: AgentConnection, timeout: float=60.0) -> None:
    """
    Send a BASELINE_CREATE command to the given agent and wait for a result.

    On success, prints a baseline summary.
    """
    if agent.agent_id is None:
        print('[!] Cannot send BASELINE_CREATE: agent_id is unknown.')
        return

    cmd_id = controller.next_command_id()
    cmd_msg = {
        'type': 'command',
        'command': 'BASELINE_CREATE',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent BASELINE_CREATE request to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send BASELINE_CREATE: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)

    if reply is None:
        print('[!] No response to BASELINE_CREATE (timeout or connection closed).')
        print("Marking agent as disconnected and removing it from the list.")
        return

    status = reply.get('status')
    details = reply.get('details') or {}
    summary = details.get('summary') or {}
    message=details.get('message','')

    if status != 'ok':
        print(f'[!] BASELINE_CREATE error from {agent.label()}: {status} - {message}')
        return

    print_baseline_summary(agent, summary)

def prompt_fim_paths_for_agent(agent: AgentConnection) -> list[str]:
    """
    Interactively ask the user which file paths to monitor for FIM
    for the given agent.
    """
    print(f'[CFG] Configuring FIM paths for {agent.label()}...')
    print('Enter file paths to monitor, comma-seperated.')
    print('Example: C:\\os\\System32\\folder_name\\folder_name\\file_name, C:\\important\\config.ini')
    raw = input('Leave blank if you want to CLEAR all FIM paths (and just hit Enter): ').strip()

    fim_paths: list[str] = []
    if raw:
        for part in raw.split(','):
            p=part.strip()
            if p:
                fim_paths.append(p)

    # Ask whether to include default OS-sensitive paths as well.
    defaults = DEFAULT_SENSITIVE_PATHS
    if defaults:
        print()
        print('Include default OS-sensitive paths as well?')
        print("Defaults on this controller OS:")
        for d in defaults:
            print(f"  - {d}")
        ans = input('Include defaults? [y/n] ').lower().strip()
        if ans in ('', 'y', 'yes'):
            for d in defaults:
                if d not in fim_paths:
                    fim_paths.append(d)

    print()
    print('[CFG] FIM paths to send:')
    if not fim_paths:
        print('  <none>')
    else:
        for p in fim_paths:
            print(f"  - {p}")

    confirm = input('Proceed with these FIM paths? [y/n] ').lower().strip()
    if confirm not in ('y', 'yes'):
        print('[CFG] Aborted FIM config change.')
        return []

    return fim_paths

def prompt_agent_general_config(agent: AgentConnection) -> dict:
    """
    Interactively ask the user for general agent config:
        - which monitors to enable/disable
        - resource thresholds

    Returns a params dict suitable for CONFIG_UPDATE, e.g.:
        {
            "enable_process_monitor": True,
            "cpu_spike_percent_over_baseline": 50,
            ...
        }

    Fields left blank are simply omitted (no change on agent).
    """
    print(f"[CFG] Configuring general monitoring options for {agent.label()}")
    print("Leave a field blank to keep the current value (no change).")
    print()

    params: dict ={}

    # Helper to read yes/no/blank
    def ask_bool(prompt: str) -> Optional[bool]:
        ans = input(prompt + " [y/n/blank=skip]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        return None  # user skipped

    # Toggles
    b = ask_bool("Enable process monitor?")
    if b is not None:
        params["enable_process_monitor"] = b

    b = ask_bool("Enable network monitor?")
    if b is not None:
        params["enable_network_monitor"] = b

    b = ask_bool("Enable file integrity monitor (FIM)?")
    if b is not None:
        params["enable_fim"] = b

    b = ask_bool("Enable vulnerability checks?")
    if b is not None:
        params["enable_vulncheck"] = b

    print()
    print("Resource thresholds (percent above baseline).")
    print("Example: if baseline CPU avg is 10 and you set 50,")
    print("         alerts will trigger if CPU > 60%.")
    print("Leave blank to keep existing threshold.")
    print()

    # Thresholds: CPU
    cpu_val = input("CPU spike threshold (% above baseline): ").strip()
    if cpu_val:
        try:
            params["cpu_spike_percent_over_baseline"] = float(cpu_val)
        except ValueError:
            print("[CFG] Invalid CPU threshold input; ignoring.")

    # Thresholds: RAM
    ram_val = input("RAM spike threshold (% above baseline): ").strip()
    if ram_val:
        try:
            params["ram_spike_percent_over_baseline"] = float(ram_val)
        except ValueError:
            print("[CFG] Invalid RAM threshold input; ignoring.")

    print()
    if not params:
        print("[CFG] No changes specified.")
        confirm = input("Send CONFIG_UPDATE with no changes? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("[CFG] Aborting config-agent operation.")
            return {}

    return params

def send_config_agent_update_and_wait(controller: Controller, agent: AgentConnection, timeout: float=30.0) -> None:
    """
    Interactively build a general agent config (monitor toggles, thresholds)
    and send a CONFIG_UPDATE command to the agent.
    """
    params = prompt_agent_general_config(agent)
    if not params:
        # Either user aborted or no meaningful changes, so do nothing.
        return

    cmd_id = controller.next_command_id()
    cmd_msg = {
        'type': 'command',
        'command': 'CONFIG_UPDATE',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':params,
    }
    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent CONFIG_UPDATE (general) to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send CONFIG_UPDATE: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to CONFIG_UPDATE (timeout or connection closed).')
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get("type") != "command_result":
        print(f"[?] Unexpected message type in response to CONFIG_UPDATE: {reply}")
        return

    status = reply.get("status")
    details = reply.get("details") or {}
    updated_keys = details.get("updated_keys") or []
    message=details.get("message","")

    if status != "ok":
        print(f"[!] CONFIG_UPDATE error from {agent.label()}: {status} - {message}")
        return

    print(f"[CFG] CONFIG_UPDATE success for {agent.label()}.")
    if updated_keys:
        print("      Updated keys: " + ", ".join(updated_keys))
    else:
        print("      (No keys were updated.)")

def send_config_fim_update_and_wait(controller: Controller, agent: AgentConnection, timeout: float=30.0) -> None:
    """
    Interactively prompt the user for FIM paths, then send a CONFIG_UPDATE
    command to the given agent with those fim_paths, and wait for the result.
    """
    fim_paths = prompt_fim_paths_for_agent(agent)
    if fim_paths is None:
        return
    # If user aborted, fim_paths will be [], and we still send that to clear FIM paths.
    cmd_id = controller.next_command_id()
    cmd_msg = {
        'type': 'command',
        'command': 'CONFIG_UPDATE',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{'fim_paths': fim_paths},
    }
    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent CONFIG_UPDATE (fim_paths) to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send CONFIG_UPDATE: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to CONFIG_UPDATE (timeout or connection closed).')
        print("    Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get("type") != "command_result":
        print(f"[?] Unexpected message type in response to CONFIG_UPDATE: {reply}")
        return

    if reply.get("command_id") != cmd_id or reply.get("command") != "CONFIG_UPDATE":
        print(f"[?] Received command_result that does not match our CONFIG_UPDATE: {reply}")
        return

    status = reply.get("status")
    details = reply.get("details") or {}
    message=details.get("message","")
    updated_keys = details.get("updated_keys") or []

    if status != "ok":
        print(f"[!] CONFIG_UPDATE error from {agent.label()}: {status} - {message}")
        return

    print(f"[CFG] CONFIG_UPDATE success for {agent.label()}.")
    if updated_keys:
        print("      Updated keys: " + ", ".join(updated_keys))
    else:
        print("      (No keys were updated.)")

def send_ping_and_wait(controller: Controller, agent: AgentConnection, timeout: float=5.0) -> None:
    """
    Send a PING command to the given agent and wait for a command_result.

    This function:
        - builds a 'command' message with command='PING'
        - sends it to the agent
        - waits up to 'timeout' seconds for a reply
        - prints the result to the CLI
    """
    if agent.agent_id is None:
        print(f"[!] Cannot send PING: agent_id is unknown.")
        return

    cmd_id = controller.next_command_id()

    cmd_msg = {
        'type': 'command',
        'command': 'PING',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{}
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f"[>] Sent PING to {agent.label()}, waiting for result...")
    except Exception as e:
        print(f"[!] Failed to send PING: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    # Wait for a single response from this agent.
    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to PING (timeout or connection closed).')
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get('type') != 'command_result':
        print(f"[?] Unexpected message type {reply['type']} from {agent.label()}. in response to PING.")
        return

    if reply.get('command_id') != cmd_id or reply.get('command') != 'PING':
        print(f"[?] Received command_result that does not match our PING command: {reply}")
        return

    status = reply.get('status')
    details = reply.get('details') or {}
    msg = details.get('message', '')

    if status == 'ok':
        print(f'[PONG] {agent.label()} responded with: {msg}')
    else:
        print(f'[!] PING error from {agent.label()}: {status} - {msg}')

def send_sysinfo_and_wait(controller: Controller, agent: AgentConnection, timeout: float=10.0) -> None:
    """
    Send a SYSINFO command to the given agent and wait for a command_result.
    On success, prints a concise summary of the system info.
    """
    if agent.agent_id is None:
        print('[!] Cannot send SYSINFO: agent_id is unknown.')
        return

    cmd_id = controller.next_command_id()
    cmd_msg = {
        'type': 'command',
        'command': 'SYSINFO',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        'params':{},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent SYSINFO request to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send SYSINFO: {e}")
        print("Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    # Wait for a single response from this agent.
    reply=recv_message(agent.sock, timeout=timeout)

    if reply is None:
        print('[!] No response to SYSINFO (timeout or connection closed).')
        print("    Marking agent as disconnected and removing it from the list.")
        controller.remove_agents(agent)
        return

    if reply.get('type') != 'command_result':
        print(f"[?] Unexpected message type {reply['type']} from {agent.label()}. in response to SYSINFO.")
        return

    if reply.get('command_id') != cmd_id or reply.get('command') != 'SYSINFO':
        print(f"[?] Received command_result that does not match our SYSINFO command: {reply}")
        return

    status = reply.get('status')
    details = reply.get('details') or {}
    data = details.get('data') or {}
    message=details.get('message','')

    if status != 'ok':
        print(f'[!] SYSINFO error from {agent.label()}: {status} - {message}')
        return

    # At this point, 'data' should hold the full sysinfo dict.
    # We print only a clean summary.
    print_sysinfo_summary(agent, data)

def print_sysinfo_summary(agent: AgentConnection, data: dict) -> None:
    """
    Print a concise, human-friendly summary of the sysinfo data.
    We assume 'data' is the dict returned by the agent's collect_sysinfo().
    We try to read common fields but fall back gracefully if some are missing.
    """
    hostname = data.get('hostname') or data.get('host', {}).get('hostname') or 'Unknown'
    os_name = data.get('os', {}).get('name') or 'Unknown'
    os_version = data.get('os', {}).get('version') or 'Unknown'
    cpu=data.get('hardware', {}).get('cpu_model') or 'Unknown'
    ram_gb=data.get('hardware', {}).get('ram_mb') or 'Unknown'
    ip_list=data.get('network', {}).get('primary_ip') or []
    if isinstance(ip_list, str):
        ip_list=[ip_list]
    ip_display=', '.join(ip_list) if ip_list else 'none'

    print(f"[SYSINFO] {hostname} ({agent.agent_id})")
    print(f"  OS: {os_name} {os_version}")
    print(f"  CPU: {cpu}")
    print(f"  RAM: {ram_gb} GB")
    print(f"  IP: {ip_display}")

def find_alert_by_id(controller: Controller, alert_id: int) -> dict | None:
    """
    Find a stored alert record by its controller-level ID.
    Each record looks like:
        {
            "id": int,
            "agent_id": str,
            "agent_label": str,
            "status": str,
            "raw": dict   # the original alert dict from the agent
        }
    """
    for rec in controller.alerts:
        if rec.get("id") == alert_id:
            return rec
    return None

# ------------------------------------------------------------
# Groq LLM triage helpers (OpenAI-compatible API)
# ------------------------------------------------------------
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"  # :contentReference[oaicite:4]{index=4}

def store_alert_with_triage(controller: Controller, agent: "AgentConnection", alert: dict) -> int:
    """
    Store an incoming alert and apply Groq triage rules consistently everywhere.

    Your spec:
      - process alerts:
          suspicious -> MAIN alerts list
          benign/unknown -> BENIGN bucket (hidden=True)
      - network + fim -> always MAIN alerts list (never hidden)
    """
    new_id = controller.add_alert(alert, agent)

    rec = find_alert_by_id(controller, new_id)
    if not rec:
        return new_id

    if not controller.llm_triage_enabled:
        return new_id

    raw = rec.get("raw") or {}
    if raw.get("alert_type") != "process":
        # We don't bucket-hide net/fim; they stay visible
        return new_id

    # Cache triage results so we don't call Groq repeatedly for the same process identity
    ck = _triage_cache_key_from_process_alert(raw)
    cached = controller.llm_triage_cache.get(ck)
    if cached:
        rec["triage"] = cached
    else:
        tri = groq_triage_process_alert(controller, raw)
        rec["triage"] = tri
        controller.llm_triage_cache[ck] = tri

    tri = rec.get("triage") or {}
    label = (tri.get("label") or "unknown").lower()

    # Confidence gate: only elevate to MAIN alerts when Groq is confident
    conf = tri.get("confidence", 0.0)
    try:
        conf = float(conf)
    except Exception:
        conf = 0.0

    threshold = getattr(controller, "suspicious_confidence_threshold", 0.80)

    # Default: hide into benign/unknown bucket
    should_hide = True

    if label == "suspicious" and conf >= threshold:
        # Only now do we treat it as "real suspicious"
        should_hide = False

    # Everything else goes to benign bucket (hidden=True)
    if controller.llm_hide_benign_process_alerts and should_hide:
        rec["hidden"] = True

    return new_id


def _triage_cache_key_from_process_alert(raw_alert: dict) -> str:
    """
    Build a stable key so the same process doesn't get triaged repeatedly.
    If you later add sha256/signature into the alert, swap cache key to sha256.
    """
    proc = raw_alert.get("process") or {}
    name = str(proc.get("name") or "").lower()
    exe = str(proc.get("exe") or "").lower()
    user = str(proc.get("username") or "").lower()
    cmd  = str(proc.get("cmdline") or "").lower()

    # keep cmdline short in key to prevent memory bloat
    if len(cmd) > 200:
        cmd = cmd[:200]

    return f"{name}|{exe}|{user}|{cmd}"

def _extract_json_object(text: str) -> dict | None:
    """
    Models sometimes add extra text.
    We extract the first {...} JSON object block and parse it.
    """
    if not isinstance(text, str) or not text.strip():
        return None

    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None

    blob = m.group(0)
    try:
        return json.loads(blob)
    except Exception:
        return None

def groq_triage_process_alert(controller: Controller, raw_alert: dict) -> dict:
    """
    Returns triage dict:
      {
        "label": "suspicious" | "benign" | "unknown",
        "confidence": 0.0..1.0,
        "reason": "short explanation"
      }

    Policy for Sentinel (your requirement):
      - "suspicious" => show in main alerts
      - "benign" or "unknown" => goes into benign bucket (`alerts --benign`)
    """
    api_key = _get_llm_api_key()
    if not api_key:
        return {
            "label": "unknown",
            "confidence": 0.0,
            "reason": "LLM_API_KEY not set on controller",
        }

    proc = raw_alert.get("process") or {}
    # Keep payload minimal but useful
    triage_payload = {
        "process_name": proc.get("name"),
        "exe_path": proc.get("exe"),
        "username": proc.get("username"),
        "cmdline": proc.get("cmdline"),
        "parent_name": proc.get("parent_name") or proc.get("pp_name"),
        "pid": proc.get("pid"),
    }

    system_msg = (
        "You are a security triage assistant for Windows process activity.\n"
        "Classify the process as suspicious, benign, or unknown.\n"
        "\n"
        "You MUST base your decision primarily on exe_path and cmdline.\n"
        "IGNORE any baseline/new-process meaning (do not treat 'new' as suspicious by itself).\n"
        "\n"
        "Mark SUSPICIOUS when you see strong indicators, especially:\n"
        "  - PowerShell with -enc or -EncodedCommand (treat this as suspicious even if exe_path is normal)\n"
        "  - System-like names (svchost.exe, lsass.exe, winlogon.exe, csrss.exe) running from user-writable paths\n"
        "  - Execution from user-writable paths (AppData\\Roaming, AppData\\Local\\Temp, Downloads, Desktop)\n"
        "  - UNC/network paths (\\\\server\\share\\...)\n"
        "  - Obvious script/LOLBin abuse patterns in cmdline\n"
        "\n"
        "Mark BENIGN when exe_path is a normal Windows/Program Files/WindowsApps location and cmdline looks normal.\n"
        "If cmdline or exe_path is missing and you cannot be sure, choose UNKNOWN.\n"
        "\n"
        "Return ONLY one JSON object with keys: label, confidence, reason.\n"
        "label must be one of: suspicious, benign, unknown.\n"
        "confidence must be a number between 0 and 1.\n"
        "reason must be one short sentence.\n"
    )

    user_msg = (
        "Triage this process alert using ONLY the given fields.\n"
        f"ALERT_JSON={json.dumps(triage_payload, ensure_ascii=False)}\n"
    )

    body = {
        "model": _get_llm_model(controller),
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.0,
        "max_completion_tokens": 200,
    }

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(_get_llm_api_url(), data=data, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    req.add_header("HTTP-Referer", "http://localhost")
    req.add_header("X-Title", "Sentinel")

    try:
        with urllib.request.urlopen(req, timeout=controller.groq_timeout_seconds) as resp:
            resp_text = resp.read().decode("utf-8", errors="replace")
            decoded = json.loads(resp_text)
    except urllib.error.HTTPError as e:
        # Rate limit / auth errors etc. -> fail safe to unknown bucket
        return {"label": "unknown", "confidence": 0.0, "reason": f"Groq HTTPError: {e.code}"}
    except Exception as e:
        return {"label": "unknown", "confidence": 0.0, "reason": f"Groq request failed: {e}"}

    try:
        content = decoded["choices"][0]["message"]["content"]
    except Exception:
        return {"label": "unknown", "confidence": 0.0, "reason": "Groq response missing content."}

    tri = _extract_json_object(content)
    if not isinstance(tri, dict):
        return {"label": "unknown", "confidence": 0.0, "reason": "Model did not return valid JSON."}

    label = str(tri.get("label", "unknown")).lower().strip()
    conf = tri.get("confidence", 0.0)
    reason = str(tri.get("reason", "")).strip()

    if label not in ("suspicious", "benign", "unknown"):
        label = "unknown"
    try:
        conf = float(conf)
    except Exception:
        conf = 0.0
    conf = max(0.0, min(1.0, conf))

    if not reason:
        reason = "No reason provided."

    return {"label": label, "confidence": conf, "reason": reason}

def print_alert_list(controller: Controller, status_filter: str | None = None, show_benign: bool = False) -> None:
    """
    show_benign=False -> show main alerts (not hidden)
    show_benign=True  -> show benign bucket (hidden process alerts)
    """
    if not controller.alerts:
        print("[ALERTS] No alerts stored.")
        return

    rows = []

    for rec in controller.alerts:
        raw = rec.get("raw") or {}
        alert_type = raw.get("alert_type") or "?"
        status = rec.get("status") or "?"
        summary = raw.get("summary") or ""
        agent_label = rec.get("agent_label") or rec.get("agent_id") or "?"

        if status_filter and status != status_filter:
            continue

        # bucket behavior
        if show_benign:
            # Only show hidden PROCESS alerts
            if not rec.get("hidden"):
                continue
            if alert_type != "process":
                continue
        else:
            # Main view: show all non-hidden + always show non-process
            if rec.get("hidden") and alert_type == "process":
                continue

        tri = rec.get("triage") or {}
        tri_label = (tri.get("label") or "-").upper()

        rows.append((rec["id"], alert_type, status, tri_label, agent_label, summary))

    if not rows:
        if show_benign:
            print("[ALERTS] No benign/unknown process alerts.")
        else:
            print("[ALERTS] No visible alerts.")
        return

    title = "BENIGN/UNKNOWN PROCESS ALERTS" if show_benign else "ALERTS"
    print(f"[{title}]")
    print(" ID  Type     Status     Triage       Agent                Summary")
    print("---- -------- ---------- -----------  -------------------- ------------------------------")
    for (aid, atype, status, tri_label, agent_label, summary) in rows:
        print(f"{aid:>3}  {atype:<8} {status:<10} {tri_label:<11}  {agent_label:<20} {summary[:30]}")


def print_alert_details(rec:dict) -> None:
    """
    Print detailed information for a single alert record.
    For now, we only have process alerts, so we focus on that layout.
    """
    raw = rec.get("raw") or {}
    alert_id = rec.get("id")
    alert_type = raw.get("alert_type") or "?"
    agent_label = rec.get("agent_label") or rec.get("agent_id") or "?"
    status = rec.get("status") or raw.get("status") or "?"
    created_at = raw.get("created_at") or "?"
    severity = raw.get("severity") or "?"

    print(f"[ALERT {alert_id}] [{alert_type.upper()}] from {agent_label}")
    print(f"  Status   : {status}")
    print(f"  Severity : {severity}")
    print(f"  Created  : {created_at}")
    print()

    tri = rec.get("triage")
    if tri:
        print("  LLM Triage (Groq):")
        print(f"    Label      : {tri.get('label')}")
        print(f"    Confidence : {tri.get('confidence')}")
        print(f"    Reason     : {tri.get('reason')}")
        print()

    if alert_type == "process":
        proc = raw.get("process") or {}
        name = proc.get("name") or "unknown.exe"
        pid = proc.get("pid")
        exe = proc.get("exe") or "?"
        user = proc.get("username") or "N/A"
        cpu = proc.get("cpu_percent")

        print("  Process:")
        print(f"    Name   : {name}")
        print(f"    PID    : {pid}")
        print(f"    User   : {user}")
        print(f"    Path   : {exe}")
        if isinstance(cpu, (int, float)):
            print(f"    CPU    : {cpu:.1f}%")
        print()

        reasons = raw.get("reasons") or []
        if reasons:
            print("  Reasons:")
            for r in reasons:
                print(f"    - {r}")
            print()

        summary = raw.get("summary")
        if summary:
            print(f"  Summary : {summary}")
            print()

    elif alert_type == "fim":
        path = raw.get("path") or raw.get("file_path") or "?"
        event_type = raw.get("event_type") or "?"
        before = raw.get("before") or {}
        after = raw.get("after") or {}
        attrib = raw.get("attribution") or {}

        print("  File Integrity:")
        print(f"    Event  : {event_type}")
        print(f"    Path   : {path}")
        print()

        # BEFORE
        print("  Before:")
        print(f"    Exists     : {before.get('exists')}")
        print(f"    Size (B)   : {before.get('size_bytes', before.get('size'))}")
        print(f"    MTime      : {before.get('mtime')}")
        print(f"    SHA256     : {before.get('sha256')}")
        print()

        # AFTER
        print("  After:")
        print(f"    Exists     : {after.get('exists')}")
        print(f"    Size (B)   : {after.get('size_bytes', after.get('size'))}")
        print(f"    MTime      : {after.get('mtime')}")
        print(f"    SHA256     : {after.get('sha256')}")
        print()

        # Attribution (Phase 3C.6 will populate for real)
        user = attrib.get("user", "unknown")
        proc = attrib.get("process", "unknown")
        pid = attrib.get("pid", None)

        print("  Attribution:")
        print(f"    User   : {user}")
        print(f"    Process: {proc}")
        print(f"    PID    : {pid}")
        print()

        reasons = raw.get("reasons") or []
        if reasons:
            print("  Reasons:")
            for r in reasons:
                print(f"    - {r}")
            print()

        summary = raw.get("summary")
        if summary:
            print(f"  Summary : {summary}")
            print()
    elif alert_type == "network":
        conn = raw.get("connection") or {}
        proc = raw.get("process") or {}

        rip = conn.get("remote_ip") or "?"
        rport = conn.get("remote_port") or "?"
        dns = conn.get("dns_name") or None
        status2 = conn.get("status") or "?"
        local_addr = conn.get("local_addr")

        pname = proc.get("name") or "unknown"
        pexe = proc.get("exe") or "?"
        puser = proc.get("username") or "?"

        print("  Network Connection:")
        print(f"    Process   : {pname}")
        print(f"    User      : {puser}")
        print(f"    Path      : {pexe}")
        print(f"    Remote    : {rip}:{rport}")
        if dns:
            print(f"    DNS Name  : {dns}")
        print(f"    Status    : {status2}")
        print(f"    Local     : {local_addr}")
        print()

        reasons = raw.get("reasons") or []
        if reasons:
            print("  Reasons:")
            for r in reasons:
                print(f"    - {r}")
            print()

        summary = raw.get("summary")
        if summary:
            print(f"  Summary : {summary}")
            print()


    else:
        # Fallback for future alert types.
        print("  Raw alert payload:")
        print(raw)
        print()

def handle_process_alert_actions(controller: Controller, rec: dict) -> None:
    """
    Show an action menu for a process alert and perform the chosen action.
    Actions:
        1 - Kill process on agent
        2 - Acknowledge alert
        3 - Dismiss alert
        4 - Back
    """
    raw = rec.get("raw") or {}
    proc = raw.get("process") or {}
    pid = proc.get("pid")
    exe = proc.get("exe")
    name=proc.get("name")
    username=proc.get("username")
    agent_id = rec.get("agent_id") or raw.get("agent_id")

    while True:
        print("Actions:")
        print("  [1] Kill this process on agent")
        print("  [2] Mark alert as acknowledged")
        print("  [3] Dismiss alert (ignore)")
        print("  [4] Whitelist this process (trust it)")
        print("  [5] Back to prompt")

        choice = input('Choose action [1-5]: ').strip()
        if choice not in ('1', '2', '3', '4', '5'):
            print("Invalid choice; try again.")
            continue

        if choice =='5':
            return

        if choice == '4':
            # Whitelist this process.
            name = proc.get("name")
            exe = proc.get("exe")
            user = proc.get("username")

            if not name or not exe:
                print("[!] Cannot whitelist: alert is missing name or exe.")
                continue

            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print("[!] Agent is not currently connected; cannot whitelist process on agent.")
                return

            success, msg=send_whitelist_process_and_wait(controller, agent, name=name, exe=exe, username=username, timeout=30.0)
            if success:
                print(f'[+] WHITELIST_PROCESS succeeded: {msg}')
                # Mark alert as RESOLVED via whitelist.
                rec["status"] = "RESOLVED"
                rec.setdefault("action", "whitelisted_process")
            else:
                print(f"[!] WHITELIST_PROCESS failed: {msg}")
            return

        if choice == '2':
            rec['status'] = 'ACK'
            print('[ALERT] Alert marked as acknowledged.')
            return

        if choice == '3':
            rec['status'] = 'DISMISSED'
            print('[ALERT] Alert marked as dismissed.')
            return

        if choice == '1':
            if pid is None:
                print("[!] This alert has no PID, cannot kill process.")
                continue

            name = proc.get("name")
            username=proc.get("username")

            agent=find_agent_by_id(controller, agent_id)
            if agent is None:
                print('[!] Agent is not currently connected; cannot kill process.')
                return

            try:
                pid_int=int(pid)
            except ValueError:
                print(f'[!] Invalid PID in alert: {pid!r}')
                return

            success, msg = send_kill_process_and_wait(controller, agent, pid=pid_int, exe=exe, name=name, username=username)
            if success:
                print(f'[+] KILL_PROCESS succeeded: {msg}')
                rec['status'] = 'RESOLVED'
                rec.setdefault('action', 'killed_process')
            else:
                print(f'[!] KILL_PROCESS failed: {msg}')
            return

def handle_network_alert_actions(controller: Controller, rec:dict) -> None:
    raw=rec.get("raw") or {}
    conn=raw.get("connection") or {}
    proc=raw.get("process") or {}

    ip = conn.get('remote_ip')
    remote_port = conn.get('remote_port')
    proc_name = proc.get('name')
    proc_user = proc.get('username') or '?'
    agent_id=rec.get("agent_id") or raw.get("agent_id")

    if not ip:
        print("[!] This network alert has no remote_ip, so actions are limited.")
        return

    # Optional: if you implement IP whitelist later, you can hide actions if whitelisted.
    # if ip_is_whitelisted(remote_ip): ...

    # We'll store last AbuseIPDB result in the alert record so the user can re-check decisions.
    last_reputation = rec.get("reputation")

    while True:
        print("Actions:")
        print("  [1] Check IP reputation (AbuseIPDB)")
        print("  [2] Block this IP (Windows Firewall)")
        print("  [3] Whitelist this IP (stop future alerts)")
        print("  [4] Mark alert as acknowledged")
        print("  [5] Dismiss alert (ignore)")
        print("  [6] Back to prompt")

        choice = input('Choose action [1-6]: ').strip()
        if choice not in ('1', '2', '3', '4', '5', '6'):
            print("Invalid choice; try again.")
            continue

        if choice == '6':
            return

        if choice == '5':
            rec['status'] = 'DISMISSED'
            print('[ALERT] Alert marked as dismissed.')
            return

        if choice == '3':
            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print("[!] Agent is not connected.")
                return
            ok, msg = send_add_ip_whitelist_and_wait(controller, agent, ip)
            if ok:
                print(f"[WL] {msg}")
                rec["status"] = "RESOLVED"
                rec.setdefault("action", "whitelisted_ip")
            else:
                print(f"[WL] Failed: {msg}")
            return

        if choice == '4':
            rec['status'] = 'ACK'
            print('[ALERT] Alert marked as acknowledged.')
            return

        # if not ip:
        #     print("[!] This alert has no remote IP address, cannot block IP.")
        #     continue

        if choice == '1':
            ok, msg, data = abuseipdb_check_ip(ip)
            if not ok:
                print(f'[ABUSEIPDB] Failed: {msg}')
                # Stay in menu still
                continue

            # Save it into the alert record (so you can show it later if needed)
            rec['reputation'] = data

            score=data.get('abuseConfidenceScore') or 0
            reports=data.get('totalReports') or 0
            last_reported=data.get('lastReportedAt')
            usage_type=data.get('usageType', 'Unknown')
            isp=data.get('isp', 'Unknown')
            org=data.get('organiztion', 'Unknown')
            country=data.get('countryCode', 'N/A')
            is_whitelisted=data.get('isWhitelisted', False)

            print(f"[IPCHECK] AbuseIPDB result for {ip}: {msg}")
            print('-'*44)

            # --- SPECIAL CASE: score == 0 but reports exist ---
            if score == 0 and reports > 0:
                print(f"Abuse Score     : {score} (no recent/high-confidence abuse)")
                print(f"Total Reports   : {reports}")
                if last_reported:
                    print(f"Last Reported   : {last_reported[:10]}")
                print(f"Usage Type      : {usage_type}")
                print(f"ISP             : {isp}")
                print(f"Organization    : {org}")
                print(f"Country         : {country}")
                print(f"Whitelisted     : {'Yes' if is_whitelisted else 'No'}")

                print("\n[INFO]")
                print("This IP has historical reports, but no recent or strong abuse signals.")
                print("This commonly occurs with shared cloud or CDN infrastructure.")
                print("Recommended action:")
                print("- Monitor or whitelist if expected")
                print("- Block only if behavior is suspicious in your environment\n")

            else:
                print(f"Abuse Score     : {score}")
                print(f"Total Reports   : {reports}")
                if score >= 50:
                    print("\n[!!!] WARNING")
                    print("This IP has a HIGH abuse confidence score.")
                    print("Strongly recommended action: BLOCK THIS IP.\n")
                elif reports > 0:
                    print("\n[!] CAUTION")
                    print("This IP has been reported before. Review behavior carefully.\n")

            # Stay in the menu so user can choose [2] right away
            continue

        if choice == '2':
            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print('[!] Agent is not currently connected; cannot block IP.')
                return

            ok, msg = send_block_ip_and_wait(controller, agent, ip)
            if ok:
                print(f"[+] {msg}")
                rec["status"] = "RESOLVED"
                rec.setdefault("action", "blocked_ip")
            else:
                print(f"[!] {msg}")
            return

def handle_fim_alert_actions(controller: Controller, rec: dict) -> None:
    raw = rec.get("raw") or {}
    agent_id = rec.get("agent_id") or raw.get("agent_id")

    path = raw.get("path") or raw.get("file_path") or ""
    if not path:
        print("[!] This FIM alert has no path; actions are limited.")
        return

    while True:
        print("  [1] Mark alert as acknowledged")
        print("  [2] Dismiss alert (ignore)")
        print("  [3] Update baseline for this file (accept change)")
        print("  [4] Lock down file (Admins/SYSTEM only)")
        print("  [5] Quarantine file (move + lock down)")
        print("  [6] Back to prompt")

        choice = input("Choose action [1-6]: ").strip()
        if choice not in ("1", "2", "3", "4", '6'):
            print("Invalid choice; try again.")
            continue

        if choice == "6":
            return

        if choice == "1":
            rec["status"] = "ACK"
            print("[ALERT] Alert marked as acknowledged.")
            return

        if choice == "2":
            rec["status"] = "DISMISSED"
            print("[ALERT] Alert marked as dismissed.")
            return

        if choice == "3":
            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print("[!] Agent is not currently connected; cannot update baseline.")
                return

            ok, msg, updated_item = send_fim_update_baseline_item_and_wait(controller, agent, path)
            if ok:
                print(f"[FIM] {msg}")
                rec["status"] = "RESOLVED"
                rec.setdefault("action", "updated_fim_baseline")

                # Optional: store updated baseline item on the alert record for later viewing
                if updated_item is not None:
                    rec["baseline_item_after_update"] = updated_item
            else:
                print(f"[FIM] Failed: {msg}")
            return

        if choice == "4":
            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print("[!] Agent is not currently connected; cannot lock down file.")
                return

            ok, msg, details = send_fim_lockdown_file_and_wait(controller, agent, path)
            if ok:
                print(f"[FIM] {msg}")
                rec.setdefault("action", "fim_lockdown")
                rec["status"] = "RESOLVED"
                if details:
                    rec["fim_lockdown_details"] = details
            else:
                print(f"[FIM] Failed: {msg}")
            return

        if choice == "5":
            agent = find_agent_by_id(controller, agent_id)
            if agent is None:
                print("[!] Agent is not currently connected; cannot quarantine file.")
                return

            ok, msg, details = send_fim_quarantine_file_and_wait(controller, agent, path)
            if ok:
                print(f"[FIM] {msg}")
                rec.setdefault("action", "fim_quarantine")
                rec["status"] = "RESOLVED"
                if details:
                    rec["fim_quarantine_details"] = details
            else:
                print(f"[FIM] Failed: {msg}")
            return

def poll_for_alerts(controller: Controller, poll_timeout: float=0.0) -> None:
    """
    Non-blocking / low-blocking poll for incoming alert messages from connected agents.

    This should be called from the main CLI loop between prompts.
    It:
        - checks each agent socket once,
        - if it sees a message of type 'alert', stores it and prints a one-line notification,
        - otherwise, ignores the message (for now) or logs it.

    NOTE: This version assumes no other code is currently waiting on recv_message() for that agent. We only call it when we're idle
    at the prompt (no in-flight command).
    """
    agents = controller.list_agents()
    if not agents:
        return

    # We iterate over a copy so we can safely remove agents if needed.
    for agent in list(agents):
        try:
            msg = recv_message(agent.sock, timeout=poll_timeout)
        except Exception as e:
            print(f"[?] Error while polling {agent.label()} for alerts: {e}")
            print("    Marking agent as disconnected and removing it from the list.")
            controller.remove_agents(agent)
            continue

        if msg is None:
            # No data avail, timeout, clean close.
            continue

        msg_type = msg.get("type")
        if msg_type == 'alert':
            alert = msg
            # Ensure alert_type is present; our agent will set 'process' for process alerts.
            if not alert.get("alert_type"):
                alert["alert_type"] = "process"

            if not alert.get("created_at"):
                alert["created_at"] = datetime.now(timezone.utc).isoformat(timespec='seconds')

            new_id = controller.add_alert(alert, agent)

            # ------------------------------------------------------------
            # LLM triage routing:
            # - suspicious process => main alerts
            # - benign/unknown process => benign bucket (`alerts --benign`)
            # - network/fim => always main alerts
            # ------------------------------------------------------------
            rec = find_alert_by_id(controller, new_id)
            if rec and controller.llm_triage_enabled:
                raw = rec.get("raw") or {}
                if raw.get("alert_type") == "process":
                    ck = _triage_cache_key_from_process_alert(raw)
                    cached = controller.llm_triage_cache.get(ck)
                    if cached:
                        rec["triage"] = cached
                    else:
                        tri = groq_triage_process_alert(controller, raw)
                        rec["triage"] = tri
                        controller.llm_triage_cache[ck] = tri

                    label = (rec["triage"] or {}).get("label", "unknown")

                    # Your requirement:
                    # - suspicious => visible
                    # - benign/unknown => not in main alerts, visible in `alerts --benign`
                    if controller.llm_hide_benign_process_alerts and label in ("benign", "unknown"):
                        rec["hidden"] = True




            atype = alert.get("alert_type", 'alert').upper()
            summary = alert.get("summary") or ''
            print(f"\n[ALERT] New {atype} alert from {agent.label()} (id {new_id})")
            if summary:
                print(f"        {summary}")
            print(f"        Use 'alert {new_id}' to view details.")
            print()  # blank line for readability
        else:
            # For now, we won't try to be clever with other message types
            # here; when we later have background monitoring, we might
            # only ever see 'alert' messages in this poll path.
            # You can log unexpected messages for debugging:
            # print(f"[?] Unexpected message while polling {agent.label()}: {msg}")
            pass

def find_agent_by_id(controller: Controller, agent_id: str |None) -> 'AgentConnection | None':
    """
    Find the currently connected AgentConnection with the given agent_id.
    Returns None if that agent is not connected.
    """
    if not agent_id:
        return None

    for agent in controller.list_agents():
        if agent.agent_id == agent_id:
            return agent
    return None

def send_kill_process_and_wait(
        controller: Controller,
        agent: 'AgentConnection',
        pid: int,
        exe: str|None,
        name,
        username,
        timeout: float=30.0,
) -> tuple[bool, str]:
    """
    Send a KILL_PROCESS command to the agent and wait for a command_result.

    Returns:
        (success: bool, message: str)
    """
    if agent.agent_id is None:
        return False, "Agent has no agent_id (HELLO not completed)"

    cmd_id = controller.next_command_id()

    cmd_msg = {
        'type': 'command',
        'command': 'KILL_PROCESS',
        'command_id': cmd_id,
        'agent_id': agent.agent_id,
        "params": {
            "pid": pid,
            "name": name,          # NEW
            "exe": exe,
            "username": username,  # NEW
        },
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent KILL_PROCESS (PID {pid}) to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send KILL_PROCESS: {e}")
        controller.remove_agents(agent)
        return False, f"Failed to send command: {e}"

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print('[!] No response to KILL_PROCESS (timeout or connection closed).')
        controller.remove_agents(agent)
        return False, "No response from agent (timeout or disconnect)"

    if reply.get("type") != "command_result":
        return False, f'Unexpected reply type: {reply}'

    if reply.get("command_id") != cmd_id or reply.get("command") != "KILL_PROCESS":
        return False, f'Reply did not match our KILL_PROCESS command: {reply}'

    status = reply.get("status")
    details = reply.get("details") or {}
    message=details.get("message","")

    if status != "ok":
        return False, message or f'KILL_PROCESS failed with status {status}'
    return True, message or 'Process killed successfully.'

def send_block_ip_and_wait(controller: Controller, agent: 'AgentConnection', ip: str, timeout:float=30.0):
    cmd_id = controller.next_command_id()

    cmd_msg = {
        "type": "command",
        "command": "BLOCK_IP",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"ip": ip},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f"[>] Sent BLOCK_IP to {agent.label()}, waiting for response...")
    except Exception as e:
        controller.remove_agents(agent)
        return False, f"Failed to send BLOCK_IP: {e}"

    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        reply = recv_message(agent.sock, timeout=1)
        if reply is None:
            continue

        msg_type = reply.get("type")

        # 🔹 CASE 1: background alert arrives → store it
        if msg_type == "alert":
            new_id = store_alert_with_triage(controller, agent, reply)
            # Optional: avoid noisy prints for benign bucket
            rec = find_alert_by_id(controller, new_id)
            if rec and rec.get("hidden"):
                continue
            print(f"[ALERT] New alert received while waiting (id {new_id}).")
            continue

        # 🔹 CASE 2: command_result arrives
        if msg_type == "command_result":
            if reply.get("command_id") != cmd_id:
                # Result for a different command — ignore
                continue

            if reply.get("status") != "ok":
                return False, (reply.get("details") or {}).get("message", "BLOCK_IP failed.")

            return True, (reply.get("details") or {}).get("message", "Blocked.")

        # 🔹 Anything else → ignore
        print(f"[DEBUG] Ignoring unexpected message while waiting: {reply}")

    return False, "Timed out waiting for BLOCK_IP response."

def send_fim_update_baseline_item_and_wait(
    controller: Controller,
    agent: "AgentConnection",
    path: str,
    timeout: float = 30.0,
) -> tuple[bool, str, dict | None]:
    """
    Tell agent to update baseline for ONE file path.
    Returns: (ok, message, updated_item_or_none)
    """
    if agent.agent_id is None:
        return False, "Agent has no agent_id (HELLO not completed).", None

    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "FIM_UPDATE_BASELINE_ITEM",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"path": path},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f"[>] Sent FIM_UPDATE_BASELINE_ITEM to {agent.label()}, waiting for response.")
    except Exception as e:
        controller.remove_agents(agent)
        return False, f"Failed to send FIM_UPDATE_BASELINE_ITEM: {e}", None

    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        reply = recv_message(agent.sock, timeout=1)
        if reply is None:
            continue

        msg_type = reply.get("type")

        # Background alert arrives while waiting
        if msg_type == "alert":
            new_id = store_alert_with_triage(controller, agent, reply)
            # Optional: avoid noisy prints for benign bucket
            rec = find_alert_by_id(controller, new_id)
            if rec and rec.get("hidden"):
                continue
            print(f"[ALERT] New alert received while waiting (id {new_id}).")
            continue

        if msg_type == "command_result":
            if reply.get("command_id") != cmd_id:
                continue

            details = reply.get("details") or {}
            if reply.get("status") != "ok":
                return False, details.get("message", "Baseline update failed."), None

            return True, details.get("message", "Baseline updated."), (details.get("item") or None)

        print(f"[DEBUG] Ignoring unexpected message while waiting: {reply}")

    return False, "Timed out waiting for baseline update response.", None

def send_fim_lockdown_file_and_wait(
    controller: Controller,
    agent: "AgentConnection",
    path: str,
    timeout: float = 30.0,
) -> tuple[bool, str, dict | None]:
    """
    Tell agent to lock down a file so only SYSTEM + Administrators have access.
    Returns: (ok, message, details_or_none)
    """
    if agent.agent_id is None:
        return False, "Agent has no agent_id (HELLO not completed).", None

    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "FIM_LOCKDOWN_FILE",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"path": path},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f"[>] Sent FIM_LOCKDOWN_FILE to {agent.label()}, waiting for response.")
    except Exception as e:
        controller.remove_agents(agent)
        return False, f"Failed to send FIM_LOCKDOWN_FILE: {e}", None

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = recv_message(agent.sock, timeout=1)
        if reply is None:
            continue

        msg_type = reply.get("type")

        # background alerts while waiting
        if msg_type == "alert":
            new_id = store_alert_with_triage(controller, agent, reply)
            rec = find_alert_by_id(controller, new_id)
            if rec and rec.get("hidden"):
                continue
            print(f"[ALERT] New alert received while waiting (id {new_id}).")
            continue

        if msg_type == "command_result" and reply.get("command_id") == cmd_id:
            details = reply.get("details") or {}
            if reply.get("status") != "ok":
                return False, details.get("message", "Lockdown failed."), details or None
            return True, details.get("message", "File locked down."), details or None

        print(f"[DEBUG] Ignoring unexpected message while waiting: {reply}")

    return False, "Timed out waiting for lockdown response.", None


def send_fim_quarantine_file_and_wait(
    controller: Controller,
    agent: "AgentConnection",
    path: str,
    timeout: float = 45.0,
) -> tuple[bool, str, dict | None]:
    """
    Tell agent to quarantine a file (move to quarantine folder + lock down).
    Returns: (ok, message, details_or_none)
    """
    if agent.agent_id is None:
        return False, "Agent has no agent_id (HELLO not completed).", None

    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "FIM_QUARANTINE_FILE",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"path": path},
    }

    try:
        send_message(agent.sock, cmd_msg)
        print(f"[>] Sent FIM_QUARANTINE_FILE to {agent.label()}, waiting for response.")
    except Exception as e:
        controller.remove_agents(agent)
        return False, f"Failed to send FIM_QUARANTINE_FILE: {e}", None

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = recv_message(agent.sock, timeout=1)
        if reply is None:
            continue

        msg_type = reply.get("type")

        # background alerts while waiting
        if msg_type == "alert":
            new_id = store_alert_with_triage(controller, agent, reply)
            rec = find_alert_by_id(controller, new_id)
            if rec and rec.get("hidden"):
                continue
            print(f"[ALERT] New alert received while waiting (id {new_id}).")
            continue

        if msg_type == "command_result" and reply.get("command_id") == cmd_id:
            details = reply.get("details") or {}
            if reply.get("status") != "ok":
                return False, details.get("message", "Quarantine failed."), details or None
            return True, details.get("message", "File quarantined."), details or None

        print(f"[DEBUG] Ignoring unexpected message while waiting: {reply}")

    return False, "Timed out waiting for quarantine response.", None


def send_whitelist_process_and_wait(
    controller: Controller,
    agent: "AgentConnection",
    name: str,
    exe: str,
    username: str | None,
    timeout: float = 30.0,
) -> tuple[bool, str]:
    """
    Send a WHITELIST_PROCESS command to the agent and wait for a command_result.

    Returns:
        (success: bool, message: str)
    """
    if agent.agent_id is None:
        return False, "Agent has no agent_id (HELLO not completed)"

    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "WHITELIST_PROCESS",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"name": name, "exe": exe, "username": username},
    }
    try:
        send_message(agent.sock, cmd_msg)
        print(f'[>] Sent WHITELIST_PROCESS ({name} @ {exe}) to {agent.label()}, waiting for response...')
    except Exception as e:
        print(f"[!] Failed to send WHITELIST_PROCESS: {e}")
        controller.remove_agents(agent)
        return False, f"Failed to send command: {e}"

    reply=recv_message(agent.sock, timeout=timeout)
    if reply is None:
        print("[!] No response to WHITELIST_PROCESS (timeout or connection closed).")
        controller.remove_agents(agent)
        return False, "No response from agent (timeout or disconnect)."

    if reply.get("type") != "command_result":
        return False, f"Unexpected reply type: {reply}"

    if reply.get("command_id") != cmd_id or reply.get("command") != "WHITELIST_PROCESS":
        return False, f"Reply did not match our WHITELIST_PROCESS command: {reply}"

    status=reply.get("status")
    details=reply.get("details") or {}
    message=details.get("message","")

    if status != "ok":
        return False, message or f"WHITELIST_PROCESS failed with status {status}"
    return True, message or "Process whitelisted successfully."

def send_get_blocked_ips_and_wait(controller: Controller, agent: "AgentConnection", timeout: float = 15.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "GET_BLOCKED_IPS",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {},
    }

    send_message(agent.sock, cmd_msg)
    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for GET_BLOCKED_IPS.", []

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "GET_BLOCKED_IPS failed."), []

    blocked = (reply.get("details") or {}).get("blocked_ips") or []
    return True, "ok", blocked

def send_unblock_ip_and_wait(controller: Controller, agent: "AgentConnection", ip: str, timeout: float = 30.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "UNBLOCK_IP",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"ip": ip},
    }

    send_message(agent.sock, cmd_msg)
    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for UNBLOCK_IP."

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "UNBLOCK_IP failed.")

    return True, (reply.get("details") or {}).get("message", "Unblocked.")

def send_get_ip_whitelist_and_wait(controller: Controller, agent: "AgentConnection", timeout: float = 15.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "GET_IP_WHITELIST",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {},
    }
    send_message(agent.sock, cmd_msg)

    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for GET_IP_WHITELIST.", []

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "GET_IP_WHITELIST failed."), []

    wl = (reply.get("details") or {}).get("network_ip_whitelist") or []
    return True, "ok", wl

def send_add_ip_whitelist_and_wait(controller: Controller, agent: "AgentConnection", ip: str, timeout: float = 15.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "ADD_IP_WHITELIST",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"ip": ip},
    }
    send_message(agent.sock, cmd_msg)

    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for ADD_IP_WHITELIST."

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "ADD_IP_WHITELIST failed.")

    return True, (reply.get("details") or {}).get("message", "Whitelisted.")

def send_remove_ip_whitelist_and_wait(controller: Controller, agent: "AgentConnection", ip: str, timeout: float = 15.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "REMOVE_IP_WHITELIST",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {"ip": ip},
    }
    send_message(agent.sock, cmd_msg)

    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for REMOVE_IP_WHITELIST."

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "REMOVE_IP_WHITELIST failed.")

    return True, (reply.get("details") or {}).get("message", "Removed.")

def send_clear_ip_whitelist_and_wait(controller: Controller, agent: "AgentConnection", timeout: float = 15.0):
    cmd_id = controller.next_command_id()
    cmd_msg = {
        "type": "command",
        "command": "CLEAR_IP_WHITELIST",
        "command_id": cmd_id,
        "agent_id": agent.agent_id,
        "params": {},
    }
    send_message(agent.sock, cmd_msg)

    reply = wait_for_command_result(controller, agent, cmd_id, timeout)
    if reply is None:
        return False, "Timed out waiting for CLEAR_IP_WHITELIST."

    if reply.get("status") != "ok":
        return False, (reply.get("details") or {}).get("message", "CLEAR_IP_WHITELIST failed.")

    return True, (reply.get("details") or {}).get("message", "Cleared.")

def wait_for_command_result(controller: Controller, agent: "AgentConnection", cmd_id: int, timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = recv_message(agent.sock, timeout=1)
        if msg is None:
            continue

        # If alerts arrive while waiting, store them
        if msg.get("type") == "alert":
            store_alert_with_triage(controller, agent, msg)
            continue

        if msg.get("type") == "command_result" and msg.get("command_id") == cmd_id:
            return msg

        # Ignore anything else
    return None

def get_agent_by_index(controller: Controller, idx_str: str) -> AgentConnection | None:
    """
        Convert a 1-based agent index (string from CLI) into an AgentConnection.
        Returns None if invalid.
        """
    try:
        idx = int(idx_str)
    except ValueError:
        print('Usage: <command> N   (N must be a number from "agents")')
        return None

    agents = controller.list_agents()
    if idx < 1 or idx > len(agents):
        print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
        return None

    return agents[idx - 1]

def main() -> int:
    """
    Entry point for the Sentinel Guard Controller (Phase 1 skeleton).

    Features:
    - Start a TCP server on 0.0.0.0:9000.
    - Accept agent connections in the background.
    - Provide a minimal CLI:
        - help
        - agents
        - quit / exit
    """
    controller = Controller(host="0.0.0.0", port=9000)
    controller.start()

    banner = pyfiglet.figlet_format(font='sub-zero', text="Sentinel")
    print(banner)
    print("Sentinel Guard Controller")
    print("=========================")
    print(f"Listening on {controller.host}:{controller.port}")
    print("Type 'help' for commands.\n")

    try:
        while True:
            # 🔔 Check for any incoming alerts before showing the prompt.
            # We use poll_timeout=0.0 so it doesn't block; it just peeks.
            poll_for_alerts(controller, poll_timeout=0.0)

            try:
                command = input("sentinel> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting Controller...")
                break

            # Empty command: just press Enter -> ignore.
            if not command:
                continue

            parts = command.split()
            cmd=parts[0]
            args=parts[1:]

            if command in ("quit", "exit"):
                print("Shutting down controller...")
                break

            if command == "help":
                print("Available commands:")
                print("  help    - Show this help message")
                print("  agents  - List connected agents")
                print("  ping N  - Send PING to agent #N (as listed by 'agents')")
                print("  sysinfo N     - Request SYSINFO from agent #N")
                print("  baseline N    - Create/refresh baseline on agent #N")
                print("  baseline-show N- Show existing baseline summary on agent #N")
                print("  config-fim N  - Configure FIM paths on agent #N")
                print("  config-agent N - Configure monitoring toggles/thresholds on agent #N")
                print("  config-show N  - Show current config for agent #N")
                print("  proc-scan N     - Run a one-shot suspicious process scan on agent #N")
                print("  alerts          - List stored alerts")
                print("  alert N         - Show details for alert with ID N")
                print('  blocked-ips N   - Show firewall-blocked IPs on agent N')
                print('  unblock-ip N IP - Remove a firewall block rule for IP on agent N')
                print('  ip-whitelist N  - Show IP whitelist on agent N')
                print('  ip-whitelist-add N IP - Add IP to whitelist on agent N')
                print('  ip-whitelist-remove N IP - Remove IP from whitelist on agent N')
                print('  ip-whitelist-clear N - Clear IP whitelist on agent N')
                print("  alerts [STATUS] [--benign]      Show alerts. Default shows suspicious process + all net/fim.")
                print("                                 Use --benign to view benign/unknown process bucket.")
                print("                                 Examples: alerts | alerts --benign | alerts NEW --benign")

                print("  quit    - Exit the controller")
                print("  exit    - Same as 'quit'")
                continue

            if command == "agents":
                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                else:
                    print("Connected agents:")
                    for idx, agent in enumerate(agents, start=1):
                        print(f"  {idx}) {agent.label()}")
                continue

            if command.startswith('ping'):
                parts = command.split()
                if len(parts) != 2:
                    print('Usage: ping N (where N is the agent number shown in "agents")')
                    continue

                try:
                    idx=int(parts[1])
                except ValueError:
                    print("Usage: ping N (N must be a number)")
                    continue

                agents = controller.list_agents()
                if idx <= 0 or idx > len(agents):
                    print(f"Invalid agent number: {idx}. Use 'agents' to see valid numbers.")
                    continue

                agents = agents[idx-1]
                send_ping_and_wait(controller, agents)
                continue

            if command.startswith('sysinfo'):
                parts = command.split()
                if len(parts) != 2:
                    print('Usage: sysinfo N (where N is the agent number shown in "agents")')
                    continue

                try:
                    idx=int(parts[1])
                except ValueError:
                    print("Usage: sysinfo N (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agents = agents[idx-1]
                send_sysinfo_and_wait(controller, agents)
                continue

            if cmd == "baseline":
                if len(args) != 1:
                    print('Usage: baseline N (where N is the agent number shown in "agents")')
                    continue
                try:
                    idx=int(args[0])
                except ValueError:
                    print("Usage: baseline N (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agents = agents[idx-1]
                send_baseline_create_and_wait(controller, agents)
                continue

            if command.startswith('config-fim'):
                parts = command.split()
                if len(parts) != 2:
                    print("Usage: config-fim N  (where N is the agent number from 'agents')")
                    continue

                try:
                    idx = int(parts[1])
                except ValueError:
                    print("Usage: config-fim N  (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f"Invalid agent number {idx}. Use 'agents' to see valid numbers.")
                    continue

                agent = agents[idx - 1]
                send_config_fim_update_and_wait(controller, agent)
                continue

            if command.startswith('config-agent'):
                parts = command.split()
                if len(parts) != 2:
                    print("Usage: config-agent N  (where N is the agent number from 'agents')")
                    continue

                try:
                    idx = int(parts[1])
                except ValueError:
                    print("Usage: config-agent N  (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f"Invalid agent number {idx}. Use 'agents' to see valid numbers.")
                    continue

                agent = agents[idx - 1]
                send_config_agent_update_and_wait(controller, agent)
                continue

            if command.startswith('config-show'):
                parts = command.split()
                if len(parts) != 2:
                    print("Usage: config-show N  (where N is the agent number from 'agents')")
                    continue
                try:
                    idx = int(parts[1])
                except ValueError:
                    print("Usage: config-show N  (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue
                if idx < 1 or idx > len(agents):
                    print(f"Invalid agent number {idx}. Use 'agents' to see valid numbers.")
                    continue

                agent = agents[idx - 1]
                send_config_get_and_wait(controller, agent)
                continue

            if cmd == 'baseline-show':
                if len(args) != 1:
                    print('Usage: baseline-show N (where N is the agent number shown in "agents")')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print("Usage: baseline-show N (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f"Invalid agent number: {idx}. Use 'agents' to see valid numbers.")
                    continue

                agents = agents[idx-1]
                send_baseline_get_and_wait(controller, agents)
                continue

            if cmd == 'proc-scan':
                if len(args) != 1:
                    print('Usage: proc-scan N (where N is the agent number shown in "agents")')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print("Usage: proc-scan N (N must be a number)")
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agent = agents[idx-1]
                send_proc_scan_and_wait(controller, agent)
                continue

            if cmd == "alerts":
                status_filter = None
                show_benign = False

                # examples:
                #   alerts
                #   alerts NEW
                #   alerts --benign
                #   alerts NEW --benign
                for a in args:
                    if a.lower() == "--benign":
                        show_benign = True
                    else:
                        status_filter = a.upper()

                print_alert_list(controller, status_filter=status_filter, show_benign=show_benign)
                continue

            if cmd == 'alert':
                if len(args) != 1:
                    print("Usage: alert N  (where N is the alert ID shown in 'alerts')")
                    continue

                try:
                    alert_id = int(args[0])
                except ValueError:
                    print("Usage: alert N  (N must be a number)")
                    continue

                rec = find_alert_by_id(controller, alert_id)
                if not rec:
                    print(f"[ALERTS] No alert found with ID {alert_id}.")
                    continue

                # Update status from NEW -> OPEN when viewed.
                if rec.get("status") == "NEW":
                    rec["status"] = "OPEN"

                print_alert_details(rec)

                raw = rec.get("raw") or {}
                alert_type = raw.get("alert_type")

                # For now, only process alerts have actions.
                if alert_type == "process":
                    handle_process_alert_actions(controller, rec)
                elif alert_type == "network":
                    handle_network_alert_actions(controller, rec)
                elif alert_type == 'fim':
                    handle_fim_alert_actions(controller, rec)
                continue
            if cmd == "blocked-ips":
                if len(args) != 1:
                    print('Usage: blocked-ips N   (N is agent number from "agents")')
                    continue

                agent = get_agent_by_index(controller, args[0])
                if not agent:
                    continue

                ok, msg, blocked = send_get_blocked_ips_and_wait(controller, agent)
                if not ok:
                    print(f"[FW] {msg}")
                    continue

                print(f"[FW] Blocked IPs on {agent.label()}:")
                if not blocked:
                    print("  (none)")
                else:
                    for i, ip in enumerate(blocked, 1):
                        print(f"  [{i}] {ip}")
                continue

            if cmd == "unblock-ip":
                if len(args) != 2:
                    print('Usage: unblock-ip N IP   (N is agent number, IP is address)')
                    continue

                agent = get_agent_by_index(controller, args[0])
                if not agent:
                    continue

                ip = args[1]
                ok, msg = send_unblock_ip_and_wait(controller, agent, ip)
                if ok:
                    print(f"[FW] {msg}")
                else:
                    print(f"[FW] Failed: {msg}")
                continue

            if cmd == "ip-whitelist":
                if len(args) != 1:
                    print('Usage: ip-whitelist N   (N is agent number from "agents")')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print('Usage: ip-whitelist N   (N must be a number)')
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agent = agents[idx - 1]

                ok, msg, wl = send_get_ip_whitelist_and_wait(controller, agent)
                if not ok:
                    print(f"[WL] {msg}")
                    continue

                print(f"[WL] IP whitelist on {agent.label()}:")
                if not wl:
                    print("  (none)")
                else:
                    for i, ip in enumerate(wl, 1):
                        print(f"  [{i}] {ip}")
                continue

            if cmd == "ip-whitelist-add":
                if len(args) != 2:
                    print('Usage: ip-whitelist-add N IP')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print('Usage: ip-whitelist-add N IP   (N must be a number)')
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agent = agents[idx - 1]
                ip = args[1].strip()

                ok, msg = send_add_ip_whitelist_and_wait(controller, agent, ip)
                if ok:
                    print(f"[WL] {msg}")
                else:
                    print(f"[WL] Failed: {msg}")
                continue

            if cmd == "ip-whitelist-remove":
                if len(args) != 2:
                    print('Usage: ip-whitelist-remove N IP')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print('Usage: ip-whitelist-remove N IP   (N must be a number)')
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agent = agents[idx - 1]
                ip = args[1].strip()

                ok, msg = send_remove_ip_whitelist_and_wait(controller, agent, ip)
                if ok:
                    print(f"[WL] {msg}")
                else:
                    print(f"[WL] Failed: {msg}")
                continue

            if cmd == "ip-whitelist-clear":
                if len(args) != 1:
                    print('Usage: ip-whitelist-clear N')
                    continue

                try:
                    idx = int(args[0])
                except ValueError:
                    print('Usage: ip-whitelist-clear N   (N must be a number)')
                    continue

                agents = controller.list_agents()
                if not agents:
                    print("No agents connected.")
                    continue

                if idx < 1 or idx > len(agents):
                    print(f'Invalid agent number: {idx}. Use "agents" to see valid numbers.')
                    continue

                agent = agents[idx - 1]

                ok, msg = send_clear_ip_whitelist_and_wait(controller, agent)
                if ok:
                    print(f"[WL] {msg}")
                else:
                    print(f"[WL] Failed: {msg}")
                continue
            # Unknown command
            print(f"Unknown command: {command!r}. Type 'help' for a list of commands.")
            continue

    except KeyboardInterrupt:
        # Ctrl+C anywhere in the loop
        print("\nCtrl+C detected. Exiting controller...")

    finally:
        controller.stop()
        print("Controller stopped.")
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
