# sentinel_agent.py
# ------------------
# Main entry point for the Sentinel Agent.
#
# Current responsibilities:
#   - Load or create the agent configuration.
#   - Print a startup summary.
#   - Connect to the controller and send a "hello" message.
#
# Later, this file will also:
#   - Handle reconnection logic.
#   - Listen for commands (PING, SYSINFO, etc.).
#   - Run the monitoring engine and send alerts.

from sentinel_config import load_or_create_config
import sys
import socket
import time
import sys

from sentinel_protocol import send_message


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

def connect_and_hello(cfg: dict) -> None:
    """
    Connect to the controller once and send a 'hello' message.

    This is the very first version of the agent's network behaviour:
        - Read controller host/port from config.
        - Open a TCP connection.
        - Send a JSON 'hello' with agent_id, display_name, and capabilities.
        - Keep the connection open (sleep in a loop for now).

    Later, this function will be extended with:
        - retry logic if the controller is down,
        - a loop to receive commands from the controller,
        - clean shutdown handling.
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
        send_message(sock, hello_msg)
        print('[+] Sent hello message to controller.')
    except Exception as e:
        print(f"[!] Failed to send hello message: {e}")
        sock.close()
        return
    # For now, we keep the connection open and just sleep.
    # In later phases, this is where we'll:
    #   - listen for commands from the controller (PING, SYSINFO, etc.)
    #   - send alerts and monitoring data.
    try:
        print("Agent is now idle but connected. (Ctrl+C to quit) )")
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Agent interrupted by user, closing connection...")
    finally:
        sock.close()
        print("[*] Agent socket closed.")

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
    connect_and_hello(cfg)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())