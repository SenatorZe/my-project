# sentinel_controller.py
# -----------------------
# Main entry point for the Sentinel Controller.
# Phase 1 skeleton:
#   - Start a TCP server and listen for agent connections.
#   - Track connected agents (by address).
#   - Provide a minimal CLI: help, agents, quit.

import socket
import pyfiglet
import sys
import threading
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from sentinel_protocol import recv_message,send_message

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

            if command in ("quit", "exit"):
                print("Shutting down controller...")
                break

            if command == "help":
                print("Available commands:")
                print("  help    - Show this help message")
                print("  agents  - List connected agents")
                print("  ping N  - Send PING to agent #N (as listed by 'agents')")
                print("  sysinfo N     - Request SYSINFO from agent #N")
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

            # Unknown command
            print(f"Unknown command: {command!r}. Type 'help' for a list of commands.")

    except KeyboardInterrupt:
        # Ctrl+C anywhere in the loop
        print("\nCtrl+C detected. Exiting controller...")

    finally:
        controller.stop()
        print("Controller stopped.")
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
