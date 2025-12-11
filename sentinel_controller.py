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
import pyfiglet
import sys
import threading
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from datetime import datetime
from sentinel_protocol import recv_message,send_message

# Default sensitive paths we might suggest including for FIM.
DEFAULT_SENSITIVE_PATHS = [r'C:\Windows\System32\drivers\etc\hosts']

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

@dataclass
class ControllerAlert:
    """
    Represents a single alert as tracked by the controller.

    We wrap the raw alert dict sent by the agent with:
        - a controller-local numeric ID (for CLI commands like `alert 1`)
        - a status we can change over time
        - a reference to the AgentConnection that sent it
        - a parsed timestamp for easier display

    The `raw` field is the full JSON-serializable alert payload
    created by the agent (using sentinel_alerts.make_process_alert()).
    """
    id:int
    raw:dict # Full alert payload received from the agent (dict with keys like:
    status:str
    agent: AgentConnection
    created_at: datetime

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

        self.alerts: List[ControllerAlert] = []
        self._next_alert_id:int=1

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

def print_process_alerts_from_proc_scan(agent: AgentConnection, alerts: list[dict]) -> None:
    """
    Pretty-print a list of process alerts returned by PROC_SCAN.
    This is just for testing Phase 3A before we build the full alert UI.
    """
    if not alerts:
        print(f'[PROC] No suspicious process reported by {agent.label()}.')
        return

    print(f'[PROC] {len(alerts)} suspicious process(es) reported by {agent.label()}:')

    for i, alert in enumerate(alerts, start=1):
        proc=alert.get('process') or {}
        name=proc.get('name') or 'unknown.exe'
        pid = proc.get("pid")
        exe = proc.get("exe") or "?"
        user = proc.get("username") or "?"
        severity = alert.get("severity") or "?"
        reasons = alert.get("reasons") or []
        summary = alert.get("summary") or ""

        print(f"  [{i}] {name} (PID {pid}, user: {user})")
        print(f"      Path    : {exe}")
        print(f"      Severity: {severity}")
        if reasons:
            print(f"      Reasons : {', '.join(reasons)}")
        if summary:
            print(f"      Summary : {summary}")
        print()

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
    alert_count = details.get("alert_count") or 0
    alerts = details.get("alerts") or []
    message=details.get("message","")

    if status != "ok":
        print(f"[!] PROC_SCAN error from {agent.label()}: {status} - {message}")
        return

    print_process_alerts_from_proc_scan(agent, alerts)

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
            command = input("sentinel> ").strip()

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
                print("  config-agent N- Configure monitoring toggles/thresholds on agent #N")
                print("  config-show N  - Show current config for agent #N")
                print("  proc-scan N     - Run a one-shot suspicious process scan on agent #N")
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
