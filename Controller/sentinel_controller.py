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

class AgentConnection:
    """
    Represents a single connected agent.
    For now, we only track its socket and address (ip, port).
    Later we'll extend this with agent_id, display_name, capabilities, etc.
    """
    sock: socket.socket
    addr: Tuple[str, int] # (IP, Port)

    def label(self) -> str:
        """
        Human-friendly label for printing this agent in the CLI.
        Example: '192.168.1.50:54321'
        """
        ip, port =self.addr
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
        self._accepting = False # Flag used to tell the accept loop whether it should keep running.

        # List of Currently connected agents.
        self.agents: List[AgentConnection] = []

        # A simple lock to protect self.agents when accessed from multiple threads.s
        self._agent_lock = threading.Lock()

    def start(self) -> None:
        """
        Start the TCP server and begin accepting agent connections
        in a background thread.
        After this method returns:
            - The controller is listening on (host, port).
            - The CLI can keep running and use 'agents' to see new connections.
        """
        if self._server_sock is None:
            # Already started
            return

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow quick restart after exit without waiting for TIME_WAIT.
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen()

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
        """
        assert self._server_sock is not None

        while self._accepting:
            try:
                # Block here until a new client connects.
                client_sock, addr = self._server_sock.accept()
            except OSError:
                # Socket closed or error during accept; stop the loop
                break

            agent = AgentConnection(sock=client_sock, addr=addr) # Wrap the raw socket + address into our AgentConnection dataclass.

            with self._agent_lock: # Add the new agent to the list in a thread-safe way.
                self.agents.append(agent)

            ip, port = addr
            print(f'[+] Agent connected to {ip}:{port}')

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

    banner = pyfiglet.figlet_format("---Sentinel---")
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
