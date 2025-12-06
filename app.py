import nmap
import json
import psutil 
import platform
import subprocess
import logging
import base64
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Credentials for Basic Auth (แก้ไขเป็น root:BossHubRoot)
USERNAME = 'root' 
PASSWORD = 'BossHubRoot' 
LISTEN_PORT = 8989

app = Flask(__name__)

# --- Custom Exception ---
class NmapNotInstalledError(Exception):
    """Exception raised when Nmap command is not found."""
    pass

# --- Security Functions (Unchanged) ---

def check_auth(username, password):
    """This function is called to check if a username / password combination is valid."""
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

# --- Scanner Core Functions (Unchanged) ---

def run_nmap_scan(target):
    """
    Runs a detailed Nmap scan for port, service, and basic security headers.
    """
    try:
        nm = nmap.PortScanner()
        arguments = '-sV -T4 --script http-headers'
        nm.scan(target, arguments=arguments)
    except nmap.nmap.PortScannerError as e:
        if 'nmap program was not found' in str(e):
            raise NmapNotInstalledError("Nmap command not found. Please ensure it's installed.")
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

    # 1 & 5. Port and Service Check
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
    
    # 4. Basic Security Check (via Nmap script output)
    security_headers = []
    if 'hostscript' in nm[host]:
         for script in nm[host]['hostscript']:
            if script['id'] == 'http-headers':
                security_headers = script['output'].strip().split('\n')
    results['security_headers'] = security_headers

    return results

def check_local_security_and_user():
    """
    Checks for running users, resource usage, and suspicious processes (Agent role).
    """
    checks = {}
    
    # 2. ตรวจสอบ User ที่ล็อกอินอยู่ (Basic User Check)
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
    
    # 3. ตรวจสอบการแอบขุดบิตคอยน์ (Potential Cryptominer Check)
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
    
    # 6. ตรวจสอบไฟล์อันตราย (Note)
    checks['security_note'] = "การตรวจสอบไฟล์อันตรายต้องใช้เครื่องมือเฉพาะทาง (เช่น ClamAV) หรือการตรวจสอบ Hash Integrity ของไฟล์ระบบหลัก (Baseline)."

    return checks

# --- Flask Routes ---

@app.route('/', methods=['GET'])
@requires_auth 
def index():
    """Route สำหรับหน้าแรก: Render ไฟล์ index.html ที่อยู่ใน templates/"""
    app.logger.info("Rendering index.html template.")
    return render_template('index.html', api_port=LISTEN_PORT)

@app.route('/api/scan/external', methods=['POST'])
@requires_auth 
def handle_external_scan():
    """Endpoint สำหรับการสแกนภายนอก: Port, Service, Nmap Security."""
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "Target IP/Domain is required"}), 400
    
    app.logger.info(f"External scan request for target: {target}")

    try:
        results = run_nmap_scan(target)
        return jsonify(results)
    except NmapNotInstalledError as e:
        app.logger.error(f"Dependency Error: {e}")
        return jsonify({"error": str(e), "suggestion": "Ensure Nmap is installed and configured correctly (run the install script again)."}), 500
    except Exception as e:
        app.logger.error(f"External scan failed for {target}: {e}")
        return jsonify({"error": "Failed to complete external scan.", "details": str(e)}), 500

@app.route('/api/scan/internal', methods=['GET'])
@requires_auth 
def handle_internal_scan():
    """Endpoint สำหรับการตรวจสอบภายใน: Users, Processes, Crypto-mining."""
    app.logger.info("Internal scan request received.")
    try:
        results = check_local_security_and_user()
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Internal check failed: {e}")
        return jsonify({"error": "Failed to complete internal checks.", "details": str(e)}), 500

# --- Production Setup ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False) 
