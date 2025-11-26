
import platform
import socket
import getpass
from datetime import datetime, timezone
import json

try:
    import psutil
except ImportError:
    psutil = None

# sentinel_sysinfo.py
#
# This module collects system information such as
# - Hostname and logged-in username
# - OS details (Windows/Linux/Mac + versions)
# - Hardware info (CPU, RAM)
# - Network details (primary IP)
#
# Later, the Sentinel Agent will import this module and send the
# returned JSON to the Sentinel Controller.

def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable, just used to pick the right interface
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except Exception:
        # If something goes wrong, this will be the fallback ip
        return '127.0.0.1'

def get_system_info(agent_id: str='sentinel_agent-01') -> dict:
    # Timestamp used for logs, alerts, and controller sorting
    timestamp = datetime.now(timezone.utc).isoformat()

    # Host information
    hostname=socket.gethostname()
    username=getpass.getuser()

    # OS details
    os_name=platform.system()
    os_version=platform.version()
    os_release=platform.release()
    os_arch=platform.machine()

    # Hardware info (only available if psutil is installed)
    if psutil:
        cpu_cores_logical=psutil.cpu_count(logical=True)
        cpu_cores_physical=psutil.cpu_count(logical=False)
        total_ram_mb=round(psutil.virtual_memory().total / (1024 *1024))
    else:
        # None values indicate missing hardware info (still valid JSON)
        cpu_cores_logical=None
        cpu_cores_physical=None
        total_ram_mb=None

    # Determine outbound IP address
    primary_ip=get_primary_ip()

    return {
        'type': 'sysinfo',
        'agent_id': agent_id,
        'timestamp': timestamp,
        'host': {
            'hostname': hostname,
            'username': username,
        },
        'os':{
            'name': os_name,
            'version': os_version,
            'release': os_release,
            'arch': os_arch,
        },
        'hardware': {
            'cpu_model': platform.processor(),
            'cpu_cores_logical': cpu_cores_logical,
            'cpu_cores_physical': cpu_cores_physical,
            'ram_mb': total_ram_mb,
        },
        'network': {
            'primary_ip': primary_ip,
        }
    }

def validate_sysinfo_payload(data: dict) -> list[str]:
    # Returns a list of error messages, but if the list is empty, then the payload is valid
    errors: list[str]=[]

    #Top-level type check
    if not isinstance(data, dict):
        return ['Payload is not a dictionary']

    required_top=['type', 'agent_id', 'timestamp', 'host', 'os', 'hardware', 'network']
    for key in required_top:
        if key not in data:
            errors.append(f'Missing top-level key: {key}')

    # If basic keys are missing, no need to go deeper
    if errors:
        return errors

    #type must be sysinfo
    if data['type'] != 'sysinfo':
        errors.append(f'Invalid type: {data['type']!r} (expected \'sysinfo\')')

    # host block
    host=data.get('host', {})
    if not isinstance(host, dict):
        errors.append('Host is not a dict')
    else:
        if not host.get('hostname'):
            errors.append('host.hostname is missing or empty')
        if not host.get('username'):
            errors.append('host.username is missing or empty')

    #OS block
    os_block=data.get('os', {})
    if not isinstance(os_block, dict):
        errors.append('OS is not a dict')
    else:
        if not os_block.get('name'):
            errors.append('os.name is missing or empty')
        if not os_block.get('arch'):
            errors.append('os.arch is missing or empty')

    # Network block
    net=data.get('network', {})
    if not isinstance(net, dict):
        errors.append('Network is not a dict')
    else:
        if not net.get('primary_ip'):
            errors.append('network.primary_ip is missing or empty')

    return errors

if __name__ == '__main__':
    print("[Sentinel SysInfo] Collecting system information...\n")
    problems=validate_sysinfo_payload(get_system_info())
    if problems:
        print('[!] Sysinfo payload has validation issues: ')
        for p in problems:
            print('   -', p)
    else:
        print('[OK] Sysinfo payload structure looks valid.')

    print('\n----RAW JSON payload ----\n')
    print(json.dumps(get_system_info(), indent=2))