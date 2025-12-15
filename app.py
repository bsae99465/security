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

LOCK_MARKER = "[BOSSHUB-SECURE-LOCK]"

# --- Smart Signatures (High Precision) ---
# เราแยก Signature เป็นระดับความรุนแรง และระบุ Pattern ที่เจาะจงมากขึ้น
MALWARE_SIGNATURES = [
    # Critical: โค้ดที่ตั้งใจรันคำสั่งอันตรายชัดเจน
    {'pattern': r'eval\s*\(\s*base64_decode', 'desc': 'CRITICAL: Executing Base64 Code (eval)', 'risk': 'high'},
    {'pattern': r'eval\s*\(\s*gzinflate', 'desc': 'CRITICAL: Executing Compressed Code (gzinflate)', 'risk': 'high'},
    {'pattern': r'shell_exec\s*\(', 'desc': 'CRITICAL: System Command Execution', 'risk': 'high'},
    {'pattern': r'passthru\s*\(', 'desc': 'CRITICAL: System Command Execution', 'risk': 'high'},
    {'pattern': r'system\s*\(', 'desc': 'CRITICAL: System Command Execution', 'risk': 'high'},
    {'pattern': r'/bin/sh', 'desc': 'CRITICAL: Linux Shell Access', 'risk': 'high'},
    {'pattern': r'nc\s+-e', 'desc': 'CRITICAL: Reverse Shell (Netcat)', 'risk': 'high'},
    
    # Suspicious: พฤติกรรมน่าสงสัย (แต่ต้องดูบริบท)
    {'pattern': r'base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'desc': 'SUSPICIOUS: Decoding User Input (Webshell Pattern)', 'risk': 'medium'},
    {'pattern': r'stratum\+tcp', 'desc': 'MINER: Crypto Mining Protocol', 'risk': 'high'},
    {'pattern': r'xmrig', 'desc': 'MINER: XMRig Configuration', 'risk': 'high'},
]

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
                suspicious.append({"pid": conn.pid, "name": proc.name(), "laddr": f"{conn.laddr.ip}:{conn.laddr.port}", "raddr": f"{conn.raddr.ip}:{conn.raddr.port}", "risk": risk, "reasons": ", ".join(reasons)})
    except Exception as e: return {"error": str(e)}
    return suspicious

# --- NEW: Enhanced Scanning Logic ---
def scan_hosting_files(path_root='/home'):
    if platform.system() != "Linux": return {"error": "Linux Only"}
    infected = []
    count = 0
    try:
        for root, dirs, files in os.walk(path_root):
            if 'logs' in root or 'mail' in root or 'cache' in root: continue # ข้ามโฟลเดอร์ Cache เพื่อลด FP
            for file in files:
                if any(file.endswith(x) for x in ['.php', '.py', '.sh', '.pl', '.quarantined']):
                    fpath = os.path.join(root, file)
                    count += 1
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            lines = f.readlines()
                            
                            # Check Quarantined Status first
                            content_sample = "".join(lines[:20]) # Check header
                            if LOCK_MARKER in content_sample or file.endswith('.quarantined'):
                                infected.append({"path": fpath, "threats": ["ถูกระงับการทำงานแล้ว (Quarantined)"], "status": "quarantined", "snippet": "N/A"})
                                continue

                            # Line-by-line Scan for better snippet extraction
                            for i, line in enumerate(lines):
                                line_clean = line.strip()
                                if not line_clean or line_clean.startswith(('//', '#', '*')): continue # Skip comments

                                for sig in MALWARE_SIGNATURES:
                                    if re.search(sig['pattern'], line_clean, re.IGNORECASE):
                                        # Found a threat!
                                        infected.append({
                                            "path": fpath,
                                            "threats": [sig['desc']],
                                            "status": "active",
                                            "risk": sig['risk'],
                                            "snippet": f"Line {i+1}: {line_clean[:100]}..." # ตัดมาแสดงแค่ 100 ตัวอักษร
                                        })
                                        break # เจอ 1 จุดในไฟล์ ถือว่าติดเชื้อแล้ว ข้ามไปไฟล์ถัดไปเลย
                                if len(infected) > 0 and infected[-1]['path'] == fpath: break 

                    except: pass
            if count > 3000: break
    except Exception as e: return {"error": str(e)}
    return {"scanned": count, "infected": infected}

# --- 3. Action Logic ---
@app.route('/api/threats/kill_process', methods=['POST'])
@requires_auth
def kill_process():
    pid = request.json.get('pid')
    try:
        p = psutil.Process(int(pid))
        p.terminate()
        return jsonify({"status": "success", "message": f"Process {pid} ถูกปิดการทำงานแล้ว"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/api/tools/clear_temp', methods=['POST'])
@requires_auth
def clear_temp():
    try:
        cmd = "find /tmp -type f -atime +1 -delete"
        subprocess.run(cmd, shell=True)
        return jsonify({"status": "success", "message": "ล้างไฟล์ขยะใน /tmp เรียบร้อย"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

def manage_file_security(file_path, action):
    if not os.path.exists(file_path): return {"status": "error", "message": "ไม่พบไฟล์"}
    if not os.access(file_path, os.W_OK): return {"status": "error", "message": "Permission Denied"}
    try:
        if action == 'restore':
            if file_path.endswith('.quarantined'):
                os.rename(file_path, file_path.replace('.quarantined', ''))
                return {"status": "success", "message": "คืนค่าชื่อไฟล์แล้ว"}
            with open(file_path, 'r', errors='ignore') as f: content = f.read()
            if LOCK_MARKER not in content: return {"status": "error", "message": "ไฟล์นี้ไม่ได้ถูกล็อค"}
            
            lines = [l for l in content.split('\n') if LOCK_MARKER not in l and "END_LOCK" not in l]
            file_ext = os.path.splitext(file_path)[1]
            new_content = "\n".join(lines).replace("# ", "") if file_ext in ['.py','.sh'] else "\n".join(lines)
            
            with open(file_path, 'w') as f: f.write(new_content)
            return {"status": "success", "message": "คืนค่าเนื้อหาไฟล์แล้ว"}

        elif action == 'fix':
            file_ext = os.path.splitext(file_path)[1].lower()
            with open(file_path, 'r', errors='ignore') as f: content = f.read()
            if LOCK_MARKER in content: return {"status": "warning", "message": "ไฟล์ถูกล็อคอยู่แล้ว"}
            
            if file_ext == '.php':
                new_content = f"/* {LOCK_MARKER} - Disabled by BossHub */\n{content}\n/* END_LOCK */"
                with open(file_path, 'w') as f: f.write(new_content)
            elif file_ext in ['.py', '.sh', '.pl']:
                new_content = f"# {LOCK_MARKER} - Disabled by BossHub\n" + "\n".join([f"# {l}" for l in content.split('\n')])
                with open(file_path, 'w') as f: f.write(new_content)
            else:
                os.rename(file_path, file_path + ".quarantined")
            return {"status": "success", "message": "ระงับการใช้งานไฟล์เรียบร้อย"}
    except Exception as e: return {"status": "error", "message": str(e)}

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

@app.route('/api/threats/manage_file', methods=['POST'])
@requires_auth
def api_manage_file():
    data = request.json
    return jsonify(manage_file_security(data.get('path'), data.get('action')))

@app.route('/api/tools/nmap', methods=['POST'])
@requires_auth
def api_nmap(): return jsonify(run_nmap(request.json['target']))

@app.route('/api/tools/service', methods=['POST'])
@requires_auth
def api_service(): return jsonify(manage_service(request.json['service'], request.json['action']))

@app.route('/api/tools/files', methods=['POST'])
@requires_auth
def api_files(): return jsonify({"files": find_recent_files(request.json.get('days', 1))})

# Helper Functions (run_nmap, etc) remain same as before...
def run_nmap(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV -T4 -p 1-1000') 
        host = nm.all_hosts()[0]
        ports = [{'port': p, 'state': nm[host]['tcp'][p]['state'], 'service': nm[host]['tcp'][p]['name']} for p in nm[host]['tcp']]
        return {"status": nm[host].state, "ports": ports}
    except Exception as e: return {"error": str(e)}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
