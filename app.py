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
import re
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

USERNAME = 'root' 
PASSWORD = 'BossHubRoot' 
LISTEN_PORT = 8989

# --- Signatures & Constants ---
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

# --- 1. System Info & Monitoring ---
def get_system_details():
    uname = platform.uname()
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    
    # Disk
    partitions = []
    try:
        for p in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(p.mountpoint)
                partitions.append({"mount": p.mountpoint, "total": get_size(u.total), "used": get_size(u.used), "percent": u.percent})
            except: pass
    except: pass

    # Network IPs
    net_info = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if str(addr.family) == 'AddressFamily.AF_INET':
                    net_info[name] = addr.address
    except: pass

    return {
        "os": f"{uname.system} {uname.release}",
        "uptime": str(datetime.datetime.now() - boot_time).split('.')[0],
        "cpu": {"cores": psutil.cpu_count(), "percent": psutil.cpu_percent()},
        "ram": {"total": get_size(psutil.virtual_memory().total), "percent": psutil.virtual_memory().percent},
        "disk": partitions,
        "network": net_info
    }

def get_deep_security_info():
    """Firewall & Auth Logs"""
    firewall = "N/A"
    logs = []
    if platform.system() == "Linux":
        try:
            firewall = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True).stdout or "UFW Inactive"
        except: firewall = "Error checking UFW"
        
        try:
            logs = subprocess.check_output(['last', '-n', '5'], timeout=2).decode('utf-8').split('\n')
        except: logs = ["Error reading logs"]
    return {"firewall": firewall, "logs": [l for l in logs if l.strip()]}

# --- 2. Threat Hunting (Network & Process) ---
def analyze_network_threats():
    suspicious = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or (conn.raddr and conn.raddr.ip == '127.0.0.1'): continue
            
            risk = 0
            reasons = []
            
            # Check Port
            if conn.raddr and conn.raddr.port in MINING_PORTS:
                risk += 10; reasons.append(f"Mining Port {conn.raddr.port}")
            
            # Check Process
            try:
                proc = psutil.Process(conn.pid)
                if any(x in proc.name().lower() for x in ['xmrig', 'minerd', 'kworker_ds']):
                    risk += 10; reasons.append("Miner Process Name")
                if proc.exe().startswith('/tmp') or proc.exe().startswith('/dev/shm'):
                    risk += 8; reasons.append("Running from /tmp")
            except: pass

            if risk > 0:
                suspicious.append({
                    "pid": conn.pid, "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "risk": risk, "reasons": ", ".join(reasons)
                })
    except Exception as e: return {"error": str(e)}
    return suspicious

# --- 3. Malware Scanner (Hosting) ---
def scan_hosting_files(path_root='/home'):
    if platform.system() != "Linux": return {"error": "Linux Only"}
    infected = []
    count = 0
    try:
        for root, dirs, files in os.walk(path_root):
            if 'logs' in root or 'mail' in root: continue
            for file in files:
                if any(file.endswith(x) for x in ['.php', '.py', '.sh']):
                    fpath = os.path.join(root, file)
                    count += 1
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read(50000) # Read first 50KB
                            found = [desc for sig, desc in MALWARE_SIGNATURES.items() if re.search(sig, content, re.IGNORECASE)]
                            if found:
                                infected.append({"path": fpath, "threats": found})
                    except: pass
            if count > 3000: break # Safety limit
    except Exception as e: return {"error": str(e)}
    return {"scanned": count, "infected": infected}

# --- 4. System Tools (Nmap, Service, Files) ---
def run_nmap(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV -T4 -p 1-1000 --script http-headers') # Quick Scan top 1000
        host = nm.all_hosts()[0]
        ports = []
        if 'tcp' in nm[host]:
            for p in nm[host]['tcp']:
                ports.append({'port': p, 'state': nm[host]['tcp'][p]['state'], 'service': nm[host]['tcp'][p]['name']})
        return {"status": nm[host].state, "ports": ports}
    except Exception as e: raise Exception(str(e))

def manage_service(name, action):
    if action not in ['start', 'stop', 'restart', 'status']: return {"error": "Invalid action"}
    cmd = ['sudo', 'systemctl', action, name]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"output": res.stdout + res.stderr}
    except Exception as e: return {"error": str(e)}

def find_recent_files(days=1):
    cmd = ['sudo', 'find', '/', '-mount', '-path', '/proc', '-prune', '-o', '-path', '/sys', '-prune', 
           '-o', '-mtime', f'-{days}', '-type', 'f', '-print']
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode('utf-8').split('\n')
        return [x for x in out if x.strip()][:100] # Limit 100 files
    except Exception as e: return []

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
def api_threat_malware(): 
    return jsonify(scan_hosting_files(request.args.get('path', '/home')))

@app.route('/api/tools/nmap', methods=['POST'])
@requires_auth
def api_nmap():
    try: return jsonify(run_nmap(request.json['target']))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/tools/service', methods=['POST'])
@requires_auth
def api_service():
    d = request.json
    return jsonify(manage_service(d['service'], d['action']))

@app.route('/api/tools/files', methods=['POST'])
@requires_auth
def api_files():
    return jsonify({"files": find_recent_files(request.json.get('days', 1))})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
