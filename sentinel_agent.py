# sentinel_agent.py
# ------------------
# Main entry point for the Sentinel Agent.
# For now, it only loads configuration and prints a startup summary.
# Later, this file will handle connecting to the controller, receiving
# commands, and running the monitoring engine.

from sentinel_config import load_or_create_config
import sys

def _format_features(cfg: dict) -> str:
    """
    Build a short string describing which monitoring features are enabled.
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

def main() -> int:
    """
    Entry point for the Sentinel Agent.

    Current responsibilities:
        - Load or create the agent configuration.
        - Print a concise startup summary.

    Later, this function will:
        - Establish a connection to the controller.
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

    # For now, we just start up, show info, and exit.
    # In the next steps, instead of exiting, we'll proceed to:
    #   - connect_to_controller(cfg)
    #   - enter main loop

    return 0

if __name__ == "__main__":
    sys.exit(main())