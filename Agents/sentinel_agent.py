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

from sentinel_protocol import send_message, recv_message
from sentinel_config import load_or_create_config
from sentinel_sysinfo import get_system_info
import sys
import socket
import time


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
    This function does NOT know or care about reconnects.
    It just reacts to whatever command it is given.
    """
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
    else:
        # For Future commands, we can add logic here to handle them.
        print(f"[!] Received unknown command: {cmd!r}")

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

    try:
        # At this point, we consider the agent "connected".
        print('Agent is now connected and waiting for commands... (Ctrl + C to quit)')
        # MAIN RECEIVE LOOP for this session.
        while True:
            # Blocking read:
            #   - returns a dict when a full message arrives
            #   - returns None if the connection is broken / closed
            msg = recv_message(sock) # holds until message or real disconnect

            if msg is None:
                # Either:
                #   - no data and timeout (controller silent), or
                #   - socket was closed / error.
                #
                # If the controller has gone away, future reads will keep
                # returning None or errors, so we treat this as a disconnect
                # and let the outer loop handle reconnect.
                # print("[!] No message received (timeout or connection closed).")
                print("[!] Assuming controller is unavailable. Ending this session.")
                break

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