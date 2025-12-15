import nmap
import json
import psutil 
import platform
import subprocess
import logging
import base64
import os
import shutil
import datetime
import re
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

USERNAME = 'root' 
PASSWORD = 'BossHubRoot' 
LISTEN_PORT = 8989

# --- Constants & Signatures ---
# Marker เอาไว้ระบุว่าไฟล์นี้ถูกเราจัดการแล้ว
LOCK_MARKER = "[BOSSHUB-SECURE-LOCK]"

MALWARE_SIGNATURES = {
    r'eval\s*\(': 'PHP Web Shell execution',
    r'base64_decode\s*\(': 'Obfuscated Code (Base64)',
    r'shell_exec\s*\(': 'System Command Execution',
    r'passthru\s*\(': 'System Command Execution',
    r'stratum\+tcp': 'Crypto Mining Protocol',
    r'xmrig': 'XMRig Miner Config',
    r'/bin/sh -i': 'Reverse Shell',
    r'nc -e': 'Netcat Reverse Shell'
}
MINING_PORTS = [3333, 4444, 5555, 6666, 7777, 8080, 14444, 45700]

app = Flask(__name__)

# --- Auth & Helpers ---
def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response('Login Required', 401, {'WWW-Authenticate': 'Basic realm="BossHub Security"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor: return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

# --- 1. System Info ---
def get_system_details():
    uname = platform.uname()
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    partitions = []
    try:
        for p in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(p.mountpoint)
                partitions.append({"mount": p.mountpoint, "total": get_size(u.total), "percent": u.percent})
            except: pass
    except: pass
    
    net_info = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if str(addr.family) == 'AddressFamily.AF_INET': net_info[name] = addr.address
    except: pass

    return {
        "os": f"{uname.system} {uname.release}",
        "uptime": str(datetime.datetime.now() - boot_time).split('.')[0],
        "cpu": {"percent": psutil.cpu_percent()},
        "ram": {"percent": psutil.virtual_memory().percent},
        "disk": partitions,
        "network": net_info
    }

def get_deep_security_info():
    firewall = "N/A"
    logs = []
    if platform.system() == "Linux":
        try: firewall = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True).stdout or "UFW Inactive"
        except: firewall = "Error checking UFW"
        try: logs = subprocess.check_output(['last', '-n', '5'], timeout=2).decode('utf-8').split('\n')
        except: logs = ["Error reading logs"]
    return {"firewall": firewall, "logs": [l for l in logs if l.strip()]}

# --- 2. Threat Hunting ---
def analyze_network_threats():
    suspicious = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or (conn.raddr and conn.raddr.ip == '127.0.0.1'): continue
            risk = 0; reasons = []
            if conn.raddr and conn.raddr.port in MINING_PORTS:
                risk += 10; reasons.append(f"Mining Port {conn.raddr.port}")
            try:
                proc = psutil.Process(conn.pid)
                if any(x in proc.name().lower() for x in ['xmrig', 'minerd']): risk += 10; reasons.append("Miner Process")
            except: pass
            if risk > 0:
                suspicious.append({"pid": conn.pid, "laddr": f"{conn.laddr.ip}:{conn.laddr.port}", "raddr": f"{conn.raddr.ip}:{conn.raddr.port}", "risk": risk, "reasons": ", ".join(reasons)})
    except Exception as e: return {"error": str(e)}
    return suspicious

def scan_hosting_files(path_root='/home'):
    if platform.system() != "Linux": return {"error": "Linux Only"}
    infected = []
    count = 0
    try:
        for root, dirs, files in os.walk(path_root):
            if 'logs' in root or 'mail' in root: continue
            for file in files:
                # Check normal suspicious files OR files we already renamed (.quarantined)
                if any(file.endswith(x) for x in ['.php', '.py', '.sh', '.pl', '.quarantined']):
                    fpath = os.path.join(root, file)
                    count += 1
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read(50000)
                            
                            # Check if ALREADY FIXED by us
                            if LOCK_MARKER in content or file.endswith('.quarantined'):
                                infected.append({
                                    "path": fpath, 
                                    "threats": ["ถูกระงับการทำงานแล้ว (Quarantined)"], 
                                    "status": "quarantined"
                                })
                                continue

                            # Check for Malware Signatures
                            found = [desc for sig, desc in MALWARE_SIGNATURES.items() if re.search(sig, content, re.IGNORECASE)]
                            if found: 
                                infected.append({
                                    "path": fpath, 
                                    "threats": found, 
                                    "status": "active"
                                })
                    except: pass
            if count > 3000: break
    except Exception as e: return {"error": str(e)}
    return {"scanned": count, "infected": infected}

# --- 3. Quarantine & Restore Logic (Enhanced) ---

def manage_file_security(file_path, action):
    """
    Action: 'fix' (Disable/Quarantine) or 'restore' (Enable/Undo)
    """
    if not os.path.exists(file_path):
        return {"status": "error", "message": "ไม่พบไฟล์ดังกล่าว"}
    
    if not os.access(file_path, os.W_OK):
        return {"status": "error", "message": "ไม่มีสิทธิ์เขียนไฟล์ (Permission Denied)"}

    try:
        # --- RESTORE LOGIC ---
        if action == 'restore':
            if file_path.endswith('.quarantined'):
                # Restore: Rename back
                new_path = file_path.replace('.quarantined', '')
                os.rename(file_path, new_path)
                return {"status": "success", "message": f"คืนค่าชื่อไฟล์เป็น {os.path.basename(new_path)} แล้ว"}
            
            # Read content to restore
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()

            if LOCK_MARKER not in content:
                return {"status": "error", "message": "ไฟล์นี้ไม่ได้ถูกล็อคโดยระบบ หรือถูกแก้ไขไปแล้ว"}

            file_ext = os.path.splitext(file_path)[1].lower()
            new_content = content
            
            if file_ext == '.php':
                # Remove /* MARKER ... */ wrapper
                # Regex to find the wrapper and extract inner content
                pattern = re.escape(f"/* {LOCK_MARKER}") + r".*?\*/\s*(.*)"
                match = re.search(pattern, content, re.DOTALL)
                if match:
                    # Fallback: Just remove our header/footer manually to be safe
                    # Simple approach: Remove lines containing the marker and the closing */
                    lines = content.split('\n')
                    # Assuming we wrap: /* MARKER ... \n OLD_CODE \n */
                    # We strip first 3 lines and last 1 line (approx) or use logic
                    # Let's use string replace for exact match if possible, or robust parsing
                    
                    # Robust Restore for PHP:
                    # Remove start tag
                    content = content.replace(f"/* {LOCK_MARKER} - ระงับการใช้งานโดย BossHub Security */\n", "")
                    # Remove end tag
                    content = content.replace("\n/* END_LOCK */", "")
                    new_content = content
                
            elif file_ext in ['.py', '.sh', '.pl']:
                # Remove # MARKER line and uncomment others
                lines = content.split('\n')
                if LOCK_MARKER in lines[0]:
                    cleaned_lines = []
                    for line in lines[1:]: # Skip header
                        if line.startswith("# "): 
                            cleaned_lines.append(line[2:]) # Remove '# '
                        else:
                            cleaned_lines.append(line)
                    new_content = "\n".join(cleaned_lines)

            with open(file_path, 'w') as f:
                f.write(new_content)
            return {"status": "success", "message": "คืนค่าเนื้อหาไฟล์เรียบร้อยแล้ว"}

        # --- FIX / QUARANTINE LOGIC ---
        elif action == 'fix':
            file_ext = os.path.splitext(file_path)[1].lower()
            
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Prevent double locking
            if LOCK_MARKER in content:
                return {"status": "warning", "message": "ไฟล์นี้ถูกระงับการใช้งานอยู่แล้ว"}

            if file_ext == '.php':
                # PHP: Wrap in comments
                header = f"/* {LOCK_MARKER} - ระงับการใช้งานโดย BossHub Security */\n"
                footer = "\n/* END_LOCK */"
                new_content = header + content + footer
                with open(file_path, 'w') as f:
                    f.write(new_content)
                return {"status": "success", "message": "ปิดการทำงานไฟล์ PHP เรียบร้อย (Commented)"}

            elif file_ext in ['.py', '.sh', '.pl']:
                # Script: Comment every line
                lines = content.split('\n')
                new_lines = [f"# {line}" for line in lines]
                header = f"# {LOCK_MARKER} - ระงับการใช้งานโดย BossHub Security\n"
                new_content = header + "\n".join(new_lines)
                with open(file_path, 'w') as f:
                    f.write(new_content)
                return {"status": "success", "message": "ปิดการทำงานสคริปต์เรียบร้อย (# Commented)"}

            else:
                # Binary/Other: Rename
                new_path = file_path + ".quarantined"
                os.rename(file_path, new_path)
                return {"status": "success", "message": f"เปลี่ยนชื่อไฟล์เป็น {os.path.basename(new_path)}"}
        
        else:
            return {"status": "error", "message": "คำสั่งไม่ถูกต้อง"}

    except Exception as e:
        app.logger.error(f"File Manage Error: {e}")
        return {"status": "error", "message": str(e)}

# --- 4. Tools & Others ---
def run_nmap(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV -T4 -p 1-1000') 
        host = nm.all_hosts()[0]
        ports = [{'port': p, 'state': nm[host]['tcp'][p]['state'], 'service': nm[host]['tcp'][p]['name']} for p in nm[host]['tcp']]
        return {"status": nm[host].state, "ports": ports}
    except Exception as e: return {"error": str(e)}

def manage_service(name, action):
    try:
        res = subprocess.run(['sudo', 'systemctl', action, name], capture_output=True, text=True, timeout=10)
        return {"output": res.stdout + res.stderr}
    except Exception as e: return {"error": str(e)}

def find_recent_files(days=1):
    try:
        cmd = ['sudo', 'find', '/', '-mount', '-path', '/proc', '-prune', '-o', '-path', '/sys', '-prune', '-o', '-mtime', f'-{days}', '-type', 'f', '-print']
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode('utf-8').split('\n')
        return [x for x in out if x.strip()][:100]
    except: return []

# --- Routes ---
@app.route('/')
@requires_auth
def index(): return render_template('index.html')

@app.route('/api/stats')
@requires_auth
def api_stats(): return jsonify(get_system_details())

@app.route('/api/security_basic')
@requires_auth
def api_sec_basic(): return jsonify(get_deep_security_info())

@app.route('/api/threats/network')
@requires_auth
def api_threat_net(): return jsonify(analyze_network_threats())

@app.route('/api/threats/malware')
@requires_auth
def api_threat_malware(): return jsonify(scan_hosting_files(request.args.get('path', '/home')))

# รวม Route Fix/Restore ไว้ที่เดียว
@app.route('/api/threats/manage_file', methods=['POST'])
@requires_auth
def api_manage_file():
    data = request.json
    return jsonify(manage_file_security(data.get('path'), data.get('action')))

@app.route('/api/tools/nmap', methods=['POST'])
@requires_auth
def api_nmap():
    try: return jsonify(run_nmap(request.json['target']))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/tools/service', methods=['POST'])
@requires_auth
def api_service(): return jsonify(manage_service(request.json['service'], request.json['action']))

@app.route('/api/tools/files', methods=['POST'])
@requires_auth
def api_files(): return jsonify({"files": find_recent_files(request.json.get('days', 1))})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
