import nmap
import json
import psutil 
import platform
import subprocess
import logging
import base64
import os
import socket
import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Credentials
USERNAME = 'root' 
PASSWORD = 'BossHubRoot' 
LISTEN_PORT = 8989

app = Flask(__name__)

# --- Custom Exception ---
class NmapNotInstalledError(Exception):
    pass
class UnsupportedOSError(Exception):
    pass
class ServiceActionError(Exception):
    pass

# --- Security Functions ---
def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- Helper: Get Size ---
def get_size(bytes, suffix="B"):
    """Scale bytes to its proper format"""
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

# --- Scanner & System Functions ---

def get_system_details():
    """Retrieves comprehensive system information."""
    uname = platform.uname()
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.datetime.fromtimestamp(boot_time_timestamp)
    
    # Network Info
    net_info = {}
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                net_info[interface_name] = {'ip': address.address, 'netmask': address.netmask}
            elif str(address.family) == 'AddressFamily.AF_PACKET': # MAC Address
                 if interface_name not in net_info: net_info[interface_name] = {}
                 net_info[interface_name]['mac'] = address.address

    # Disk Info
    partitions = []
    try:
        for partition in psutil.disk_partitions():
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                partitions.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": get_size(partition_usage.total),
                    "used": get_size(partition_usage.used),
                    "free": get_size(partition_usage.free),
                    "percent": partition_usage.percent
                })
            except PermissionError:
                continue
    except Exception as e:
        app.logger.error(f"Error reading disk info: {e}")

    # Memory
    svmem = psutil.virtual_memory()
    
    return {
        "os": {
            "system": uname.system,
            "node_name": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "uptime": str(datetime.datetime.now() - bt).split('.')[0]
        },
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "total_cores": psutil.cpu_count(logical=True),
            "usage_per_core": psutil.cpu_percent(percpu=True, interval=1),
            "total_usage": psutil.cpu_percent()
        },
        "memory": {
            "total": get_size(svmem.total),
            "available": get_size(svmem.available),
            "used": get_size(svmem.used),
            "percent": svmem.percent
        },
        "disk": partitions,
        "network": net_info
    }

def get_firewall_status():
    """Checks UFW status on Linux."""
    if platform.system() != "Linux":
        return "Firewall check supported only on Linux."
    
    try:
        # Check UFW
        result = subprocess.run(['sudo', 'ufw', 'status', 'verbose'], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "UFW not installed."
    except Exception as e:
        return f"Error checking firewall: {str(e)}"

def get_auth_logs(lines=10):
    """Gets the last login attempts."""
    if platform.system() != "Linux":
        return ["Log check supported only on Linux."]
    
    try:
        result = subprocess.check_output(['last', '-n', str(lines)], timeout=5).decode('utf-8').split('\n')
        return [line for line in result if line.strip()]
    except Exception as e:
        return [f"Error retrieving logs: {str(e)}"]

def run_nmap_full_scan(target):
    try:
        nm = nmap.PortScanner()
        # Full scan: -p- (1-65535) with service detection
        arguments = '-sV -T4 -p- --script http-headers'
        nm.scan(target, arguments=arguments)
    except nmap.nmap.PortScannerError as e:
        if 'nmap program was not found' in str(e):
            raise NmapNotInstalledError("Nmap command not found.")
        raise Exception(f"Nmap scan failed: {e}")
    except Exception as e:
        app.logger.error(f"Error during Nmap scan: {e}")
        raise Exception(f"General error during Nmap scan: {e}")
        
    results = {}
    host_list = nm.all_hosts()
    if not host_list:
        return {"status": "down", "ports": [], "security_headers": []}

    host = host_list[0]
    results['status'] = nm[host].state
    results['address'] = host

    ports = []
    if 'tcp' in nm[host]:
        for port in sorted(nm[host]['tcp']):
            port_info = nm[host]['tcp'][port]
            ports.append({
                'port': port,
                'state': port_info.get('state', 'unknown'),
                'service': port_info.get('name', 'N/A'),
                'product': port_info.get('product', 'N/A'),
                'version': port_info.get('version', 'N/A')
            })
    results['ports'] = ports
    
    security_headers = []
    if 'hostscript' in nm[host]:
         for script in nm[host]['hostscript']:
            if script['id'] == 'http-headers':
                security_headers = script['output'].strip().split('\n')
    results['security_headers'] = security_headers
    return results

def check_local_security_and_user():
    checks = {}
    
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(['w', '-hs'], timeout=5).decode('utf-8').split('\n')
            logged_in_users = [line.strip() for line in output if line.strip()]
            checks['logged_in_users'] = logged_in_users
        except Exception as e:
             checks['logged_in_users'] = ["Error retrieving user info"]
    else:
        checks['logged_in_users'] = [f"OS: {platform.system()}"]
    
    high_cpu_processes = []
    CPU_THRESHOLD = 50 
    KNOWN_MINER_NAMES = ["xmrig", "cpuminer", "minerd", "kworker", "cryptomin"] 
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            name = proc.info['name'].lower()
            cpu_percent = proc.info['cpu_percent']
            
            if cpu_percent > CPU_THRESHOLD:
                 is_suspicious = "High Usage"
                 if any(miner in name for miner in KNOWN_MINER_NAMES):
                     is_suspicious = "Potential Miner"
                 
                 high_cpu_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu_percent': cpu_percent,
                    'type': is_suspicious
                 })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
             
    checks['high_cpu_processes'] = high_cpu_processes
    checks['security_note'] = "การตรวจสอบไฟล์อันตรายต้องใช้เครื่องมือเฉพาะทาง (ClamAV) หรือ Checksum"
    return checks

def scan_latest_files(days=1):
    if platform.system() != "Linux":
        raise UnsupportedOSError("File scanning is only supported on Linux.")

    find_command = [
        'sudo', 'find', '/',
        '-mount', 
        '-path', '/proc', '-prune', '-o',
        '-path', '/sys', '-prune', '-o',
        '-path', '/dev', '-prune', '-o',
        '-path', '/run', '-prune', '-o', 
        '-path', '/tmp', '-prune', '-o', 
        '-mtime', f'-{days}',
        '-type', 'f',
        '-print'
    ]
    try:
        output = subprocess.check_output(find_command, timeout=120, stderr=subprocess.PIPE).decode('utf-8')
        files = output.strip().split('\n')
        return [f for f in files if f.strip()]
    except Exception as e:
        raise ServiceActionError(f"File scan failed: {e}")

def manage_systemd_service(service_name, action):
    if platform.system() != "Linux":
        raise UnsupportedOSError("Linux only.")
    allowed_actions = ['status', 'start', 'stop', 'restart']
    if action not in allowed_actions:
        raise ServiceActionError(f"Invalid action: {action}")
    command = ['sudo', 'systemctl', action, service_name]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=(action != 'status'), timeout=10)
        if action == 'status':
            status_summary = [line for line in result.stdout.split('\n') if 'Active:' in line or 'Loaded:' in line]
            return {"status": "success", "summary": "\n".join(status_summary), "full_output": result.stdout}
        return {"status": "success", "message": f"Service '{service_name}' -> '{action}' OK."}
    except Exception as e:
        raise ServiceActionError(f"Error: {e}")

# --- Flask Routes ---

@app.route('/', methods=['GET'])
@requires_auth 
def index():
    return render_template('index.html', api_port=LISTEN_PORT)

@app.route('/api/server/details', methods=['GET'])
@requires_auth
def handle_server_details():
    """Endpoint for full server stats."""
    try:
        details = get_system_details()
        return jsonify(details)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/deep', methods=['GET'])
@requires_auth
def handle_deep_security():
    """Endpoint for Firewall and Auth Logs."""
    try:
        firewall = get_firewall_status()
        auth_logs = get_auth_logs()
        return jsonify({"firewall": firewall, "auth_logs": auth_logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/external', methods=['POST'])
@requires_auth 
def handle_external_scan():
    target = request.json.get('target')
    if not target: return jsonify({"error": "Target Required"}), 400
    try:
        results = run_nmap_full_scan(target) 
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/internal', methods=['GET'])
@requires_auth 
def handle_internal_scan():
    try:
        results = check_local_security_and_user()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/manage/service', methods=['POST'])
@requires_auth 
def handle_service_management():
    data = request.json
    try:
        result = manage_systemd_service(data.get('service'), data.get('action'))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 500

@app.route('/api/scan/latest_files', methods=['POST'])
@requires_auth 
def handle_latest_files_scan():
    try:
        files = scan_latest_files(request.json.get('days', 1))
        return jsonify({"status": "success", "file_count": len(files), "files": files})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
