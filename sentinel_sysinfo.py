import platform
import socket
import getpass
from datetime import datetime, timezone
import json

try:
    import psutil
except ImportError:
    psutil = None

def get_primary_ip() -> str:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()

def get_system_info(agent_id: str='sentinel_agent-01') -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    hostname=socket.gethostname()
    username=getpass.getuser()

    os_name=platform.system()
    os_version=platform.version()
    os_release=platform.release()
    os_arch=platform.machine()

    if psutil:
        cpu_cores_logical=psutil.cpu_count(logical=True)
        cpu_cores_physical=psutil.cpu_count(logical=False)
        total_ram_mb=round(psutil.virtual_memory().total / (1024 *1024))
    else:
        cpu_cores_logical=None
        cpu_cores_physical=None
        total_ram_mb=None

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

if __name__ == '__main__':
    print(json.dumps(get_system_info(), indent=2))