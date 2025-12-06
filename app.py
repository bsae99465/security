import nmap
import json
import psutil 
import platform
import subprocess
import logging
import base64
import os
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Credentials for Basic Auth
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
    """Checks if a username / password combination is valid."""
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth."""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    """Decorator to protect API routes with Basic Auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- Scanner Core Functions ---

def run_nmap_full_scan(target):
    """Runs a full Nmap scan (1-65535) for port, service, and security headers."""
    try:
        nm = nmap.PortScanner()
        # Full scan: -p- (1-65535)
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
    """Checks for running users, resource usage, and suspicious processes."""
    checks = {}
    
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(['w', '-hs'], timeout=5).decode('utf-8').split('\n')
            logged_in_users = [line.strip() for line in output if line.strip()]
            checks['logged_in_users'] = logged_in_users
        except Exception as e:
             app.logger.warning(f"Error checking logged-in users: {e}")
             checks['logged_in_users'] = ["Error retrieving user info"]
    else:
        checks['logged_in_users'] = [f"User check only supported on Linux. Current OS: {platform.system()}"]
    
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
    checks['security_note'] = "การตรวจสอบไฟล์อันตรายต้องใช้เครื่องมือเฉพาะทาง (เช่น ClamAV) หรือการตรวจสอบ Hash Integrity ของไฟล์ระบบหลัก (Baseline)."

    return checks

def scan_latest_files(days=1):
    """Scans for files created or modified in the last 'days' across the system."""
    if platform.system() != "Linux":
        raise UnsupportedOSError("File scanning is only supported on Linux.")

    # Exclude directories known to change constantly
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
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error during find command: {e.stderr.decode()}")
        raise ServiceActionError(f"Error executing file scan command.")
    except subprocess.TimeoutExpired:
        raise ServiceActionError("File scan timed out (too many files to check).")
    except Exception as e:
        raise ServiceActionError(f"File scan failed: {e}")

def manage_systemd_service(service_name, action):
    """Performs an action (status/start/stop/restart) on a systemd service."""
    if platform.system() != "Linux":
        raise UnsupportedOSError("Service management is only supported on Linux (using systemd).")

    allowed_actions = ['status', 'start', 'stop', 'restart']
    if action not in allowed_actions:
        raise ServiceActionError(f"Invalid action: {action}")

    command = ['sudo', 'systemctl', action, service_name]
    
    try:
        # Check=True is used for non-status actions to raise error if start/stop fails
        result = subprocess.run(command, capture_output=True, text=True, check=(action != 'status'), timeout=10)
        
        if action == 'status':
            status_summary = [line for line in result.stdout.split('\n') if 'Active:' in line or 'Loaded:' in line]
            return {"status": "success", "summary": "\n".join(status_summary), "full_output": result.stdout}
        
        return {"status": "success", "message": f"Service '{service_name}' successfully executed action '{action}'."}

    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip()
        if "not found" in error_output or "no such service" in error_output:
            raise ServiceActionError(f"Service '{service_name}' not found.")
        raise ServiceActionError(f"Failed to execute action '{action}' on service '{service_name}': {error_output}")
    except subprocess.TimeoutExpired:
        raise ServiceActionError(f"Action '{action}' timed out for service '{service_name}'.")
    except Exception as e:
        raise ServiceActionError(f"Unexpected error during service management: {e}")

# --- Flask Routes ---

@app.route('/', methods=['GET'])
@requires_auth 
def index():
    """Route for the main scanning interface."""
    app.logger.info("Rendering index.html template.")
    return render_template('index.html', api_port=LISTEN_PORT)

@app.route('/api/scan/external', methods=['POST'])
@requires_auth 
def handle_external_scan():
    """Endpoint for full external scan (Port 1-65535, Service, Security)."""
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "Target IP/Domain is required"}), 400
    
    app.logger.info(f"Full external scan request for target: {target}")

    try:
        results = run_nmap_full_scan(target) 
        return jsonify(results)
    except NmapNotInstalledError as e:
        return jsonify({"error": str(e), "suggestion": "Ensure Nmap is installed."}), 500
    except Exception as e:
        app.logger.error(f"External scan failed for {target}: {e}")
        return jsonify({"error": "Failed to complete external scan.", "details": str(e)}), 500

@app.route('/api/scan/internal', methods=['GET'])
@requires_auth 
def handle_internal_scan():
    """Endpoint for local security checks (Users, Processes, Crypto-mining)."""
    app.logger.info("Internal security check request received.")
    try:
        results = check_local_security_and_user()
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Internal check failed: {e}")
        return jsonify({"error": "Failed to complete internal checks.", "details": str(e)}), 500

@app.route('/api/manage/service', methods=['POST'])
@requires_auth 
def handle_service_management():
    """Endpoint for managing systemd services (start, stop, restart, status)."""
    data = request.json
    service_name = data.get('service')
    action = data.get('action')

    if not service_name or not action:
        return jsonify({"error": "Service name and action are required."}), 400

    try:
        result = manage_systemd_service(service_name, action)
        return jsonify(result)
    except UnsupportedOSError as e:
        return jsonify({"error": str(e)}), 400
    except ServiceActionError as e:
        return jsonify({"status": "failed", "error": str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unhandled error in service management: {e}")
        return jsonify({"status": "failed", "error": "An unexpected error occurred."}), 500

@app.route('/api/scan/latest_files', methods=['POST'])
@requires_auth 
def handle_latest_files_scan():
    """Endpoint for scanning recently modified files."""
    days = request.json.get('days', 1) 

    try:
        files = scan_latest_files(days)
        return jsonify({"status": "success", "days": days, "file_count": len(files), "files": files})
    except UnsupportedOSError as e:
        return jsonify({"error": str(e)}), 400
    except ServiceActionError as e:
        return jsonify({"status": "failed", "error": str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unhandled error in latest file scan: {e}")
        return jsonify({"status": "failed", "error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
