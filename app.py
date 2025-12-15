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

# --- Malware & Threat Signatures ---
# คำสั่งหรือ pattern ที่มักเจอใน Web Shell หรือ Script ขุด
MALWARE_SIGNATURES = {
    r'eval\s*\(': 'PHP Web Shell execution',
    r'base64_decode\s*\(': 'Obfuscated Code (Base64)',
    r'shell_exec\s*\(': 'System Command Execution',
    r'passthru\s*\(': 'System Command Execution',
    r'stratum\+tcp': 'Crypto Mining Protocol',
    r'xmrig': 'XMRig Miner Config',
    r'cpuminer': 'CPU Miner Config',
    r'/bin/sh -i': 'Reverse Shell',
    r'nc -e': 'Netcat Reverse Shell',
    r'fsockopen\s*\(': 'Socket Connection (Potential Reverse Shell)'
}

# Mining Ports (Common pools)
MINING_PORTS = [3333, 4444, 5555, 6666, 7777, 8080, 14444, 45700]

app = Flask(__name__)

# --- Auth Helpers ---
def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response(
    'Access Denied.\nLogin Required.', 401,
    {'WWW-Authenticate': 'Basic realm="BossHub Security"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- Core Security Logic ---

def analyze_network_connections():
    """ตรวจสอบการเชื่อมต่อ Network ที่ผิดปกติ (Packet/Connection Level)"""
    suspicious_conns = []
    try:
        # ดึง Connection ทั้งหมด (TCP/UDP)
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            # ข้าม Loopback
            if conn.raddr and conn.raddr.ip == '127.0.0.1':
                continue
            
            risk_score = 0
            risk_reasons = []

            # 1. เช็ค Port ขุด Bitcoin
            if conn.raddr and conn.raddr.port in MINING_PORTS:
                risk_score += 5
                risk_reasons.append(f"Connected to Mining Port {conn.raddr.port}")

            # 2. เช็ค Process ที่สร้าง Connection นี้
            try:
                process = psutil.Process(conn.pid)
                proc_name = process.name()
                cmdline = " ".join(process.cmdline())
                
                # เช็คชื่อ Process อันตราย
                if any(x in proc_name.lower() for x in ['xmrig', 'minerd', 'kworker_ds', 'python_backdoor']):
                    risk_score += 10
                    risk_reasons.append(f"Suspicious Process Name: {proc_name}")

                # เช็คว่ารันจาก /tmp หรือไม่ (Malware ชอบรันในนี้)
                try:
                    exe_path = process.exe()
                    if exe_path.startswith('/tmp') or exe_path.startswith('/dev/shm'):
                        risk_score += 8
                        risk_reasons.append(f"Running from temporary path: {exe_path}")
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Unknown/Kernel"
                cmdline = "N/A"

            # ถ้ามีความเสี่ยง ให้บันทึก
            if risk_score > 0 or (conn.status == 'ESTABLISHED' and conn.raddr):
                # กรองแสดงเฉพาะ Established หรือที่มีความเสี่ยงสูง
                if risk_score > 0:
                    status_label = "DANGEROUS"
                else:
                    status_label = "NORMAL"
                    continue # ถ้า Normal ไม่ต้องส่งไปรกหน้าจอ ยกเว้นอยากดู Traffic

                suspicious_conns.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "status": conn.status,
                    "pid": conn.pid,
                    "program": proc_name,
                    "risk_score": risk_score,
                    "reasons": ", ".join(risk_reasons),
                    "label": status_label
                })

    except Exception as e:
        app.logger.error(f"Network Scan Error: {e}")
        return {"error": str(e)}

    return sorted(suspicious_conns, key=lambda x: x['risk_score'], reverse=True)

def scan_hosting_scripts(path_root='/home'):
    """สแกนไฟล์ใน HestiaCP/VestaCP (/home/user/web/...) เพื่อหา Code Injection"""
    if platform.system() != "Linux":
        return {"error": "Hosting scan supports Linux only"}

    infected_files = []
    scanned_count = 0
    
    # กำหนด extension ที่จะสแกน
    target_exts = ['.php', '.py', '.sh', '.pl', '.cgi']

    try:
        # เดินดูไฟล์ใน /home (จุดที่ Web Control Panel เก็บไฟล์)
        for root, dirs, files in os.walk(path_root):
            # ข้าม Folder ระบบ หรือ Log
            if 'logs' in root or 'mail' in root:
                continue

            for file in files:
                if any(file.endswith(ext) for ext in target_exts):
                    file_path = os.path.join(root, file)
                    scanned_count += 1
                    
                    try:
                        # อ่านไฟล์แบบ Binary เพื่อหลีกเลี่ยง Encoding error แล้ว decode บางส่วน
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read(100000) # อ่านแค่ 100KB แรกเพื่อ performance
                            
                            found_sigs = []
                            for sig, desc in MALWARE_SIGNATURES.items():
                                if re.search(sig, content, re.IGNORECASE):
                                    found_sigs.append(desc)
                            
                            if found_sigs:
                                stat = os.stat(file_path)
                                infected_files.append({
                                    "path": file_path,
                                    "owner_uid": stat.st_uid,
                                    "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                    "threats": found_sigs
                                })
                    except Exception as err:
                        # Permission denied or locked file
                        continue
                        
            # Limit การสแกนเพื่อไม่ให้ Server ค้าง (Safety Cut)
            if scanned_count > 5000:
                break

    except Exception as e:
        return {"error": str(e)}

    return {
        "scanned_count": scanned_count,
        "infected_count": len(infected_files),
        "details": infected_files
    }

# --- Existing Basic Functions (Optimized) ---
def get_system_details():
    # ... (Code เดิม เก็บไว้ใช้)
    uname = platform.uname()
    return {
        "os": f"{uname.system} {uname.release}",
        "node": uname.node,
        "cpu_percent": psutil.cpu_percent(),
        "ram_percent": psutil.virtual_memory().percent
    }

# --- Flask Routes ---

@app.route('/')
@requires_auth
def index():
    return render_template('index.html', api_port=LISTEN_PORT)

@app.route('/api/scan/network_threats', methods=['GET'])
@requires_auth
def api_network_threats():
    """API: ตรวจ Packet/Connection อันตราย"""
    results = analyze_network_connections()
    return jsonify({"data": results, "count": len(results)})

@app.route('/api/scan/hosting_malware', methods=['GET'])
@requires_auth
def api_hosting_malware():
    """API: ตรวจ Script ใน Hestia/Vesta"""
    # รับ path จาก parameter หรือ default เป็น /home
    target_path = request.args.get('path', '/home')
    results = scan_hosting_scripts(target_path)
    return jsonify(results)

@app.route('/api/server/quick_stats', methods=['GET'])
@requires_auth
def api_quick_stats():
    return jsonify(get_system_details())

# ... (Routes เดิม เช่น External Scan, Service Manager ให้คงไว้ตามเดิมจากไฟล์ก่อนหน้าถ้าจำเป็น)
# เพื่อความกระชับ ผมจะใส่เฉพาะส่วนใหม่ที่สำคัญ แต่ถ้าคุณบอสต้องการรวม ผมรวมให้ได้ครับ
# (ในที่นี้ Code นี้รันได้เลยในส่วนของฟีเจอร์ใหม่)

if __name__ == '__main__':
    # ตรวจสอบสิทธิ์ Root ก่อนรัน เพราะต้องอ่าน /home ของ user อื่น
    if os.geteuid() != 0:
        print("WARNING: Script นี้ควรทำงานด้วยสิทธิ์ Root เพื่อสแกน HestiaCP/VestaCP ได้ครบทุก User")
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)
