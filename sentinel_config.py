# sentinel_config.py
# -------------------
# Handles loading, creating, and saving the Sentinel Agent configuration.
# This is where the agent gets its identity and connection settings.

import os
import json
import uuid
import socket
from typing import Any, Dict

# Config file name
CONFIG_PATH = r'C:\Users\senat\PycharmProjects\Sentinel\agent_config.json'

def get_default_config() -> Dict[str, Any]:
    # Create a default configuration dictionary for the agent.
    # This is used on the very first run when no config file exists yet.

    agent_id = f'sentinel-AGENT-{uuid.uuid4().hex[:8]}' # Unique id for the agent on first run
    display_name=socket.gethostname() # Uses the machines host name as a default display name

    #Default controller settings
    controller_host='127.0.0.1'
    controller_port=9000

    reconnect_interval_seconds=5 # How often the agent should retry connecting if cont is down

    #Monitoring feature toggles
    return {
        "agent_id": agent_id,
        "display_name": display_name,

        "controller_host": controller_host,
        "controller_port": controller_port,
        "reconnect_interval_seconds": reconnect_interval_seconds,

        # Monitoring toggles
        "enable_process_monitor": True,
        "enable_network_monitor": True,
        "enable_fim": True,
        "enable_vulncheck": True,

        # How often the main monitoring loop should run (in seconds)
        "monitor_interval_seconds": 30,

        # Logging verbosity for the agent (could be "debug", "info", "warning", etc.)
        "log_level": "info",
    }

def save_config(config: Dict[str, Any], path: str = CONFIG_PATH) -> None:
    """
    Save the given configuration dictionary to disk as JSON.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def load_config(path: str = CONFIG_PATH) -> Dict[str, Any] | None:
    # Load configuration from disk.
    # Returns the config dict if successful, or None if the file does not exist
    # or is invalid/corrupted.

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
        # Config file exists but doesn't contain a JSON object
            return None
        return data
    except (OSError, json.JSONDecodeError):
        # File unreadable or json is broken
        return None

def apply_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    # Ensure the given config dictionary has all required keys.
    # Any missing keys are filled in from the default config.
    # Existing keys are NOT overwritten.

    defaults = get_default_config()

    # Only add keys that are missing; keep user-changed values as-is
    for key, value in defaults.items():
        if key not in config:
            config[key] = value

    return config

def load_or_create_config(path: str = CONFIG_PATH) -> Dict[str, Any]:
    """
    Main entry point for the agent to obtain its configuration.

    Logic:
    - Try to load an existing config from disk.
    - If not found or invalid, create a new default config and save it.
    - Ensure all required keys exist by applying defaults.
    - Return the final config dictionary.
    """

    config = load_config(path)

    if config is None:
        # First run or corrupted config
        config = get_default_config()
        save_config(config, path)
        return config

    # Existing config loaded; make sure it has all the keys we expect.
    config = apply_defaults(config)
    # Optionally, re-save after applying defaults so the file stays up to date.
    save_config(config, path)
    return config

if __name__ == "__main__":
    """
    Quick self-test:
    - Loads or creates the agent config.
    - Prints a short summary so you can verify the values.
    """
    cfg = load_or_create_config()
    print("Sentinel Agent Configuration")
    print("-----------------------------")
    print(f"agent_id      : {cfg['agent_id']}")
    print(f"display_name  : {cfg['display_name']}")
    print(f"controller    : {cfg['controller_host']}:{cfg['controller_port']}")
    print(f"reconnect_int : {cfg['reconnect_interval_seconds']}s")
    print(f"monitor_int   : {cfg['monitor_interval_seconds']}s")
    print(f"process mon   : {cfg['enable_process_monitor']}")
    print(f"network mon   : {cfg['enable_network_monitor']}")
    print(f"FIM           : {cfg['enable_fim']}")
    print(f"vulncheck     : {cfg['enable_vulncheck']}")
    print(f"log_level     : {cfg['log_level']}")
