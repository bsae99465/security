import socket
import platform
import psutil
from flask import Flask, jsonify
import os

app = Flask(__name__)
# กำหนด Port เดียวกับที่ตั้งค่าใน server_scanner.service คือ 8989
PORT = 8989 

def check_open_ports(host='127.0.0.1', ports_to_check=None):
    """
    สแกนตรวจสอบ Port ที่เปิดอยู่บนเครื่องตัวเอง (localhost)
    """
    if ports_to_check is None:
        # Port พื้นฐานที่ควรตรวจสอบ: FTP, SSH, HTTP, HTTPS, MySQL, API
        ports_to_check = [21, 22, 80, 443, 3306, 8080,8083,2299, PORT]
    
    open_ports = []
    
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3) # ตั้งเวลา Timeout สั้นๆ เพื่อความรวดเร็ว
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            # จัดการข้อผิดพลาดที่อาจเกิดขึ้น เช่น Permission denied
            print(f"Error checking port {port}: {e}")
            
    return open_ports

def get_system_info():
    """
    ดึงข้อมูล System, CPU, Memory, และ Disk โดยใช้ไลบรารี psutil
    """
    uname = platform.uname()
    disk_usage = psutil.disk_usage('/')
    
    return {
        "os": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
        "cpu": {
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical": psutil.cpu_count(logical=True),
            # ดึงการใช้งาน CPU ใน 1 วินาทีล่าสุด
            "percent_usage": psutil.cpu_percent(interval=1), 
        },
        "memory": {
            "total_gb": round(psutil.virtual_memory().total / (1024.0 ** 3), 2),
            "available_gb": round(psutil.virtual_memory().available / (1024.0 ** 3), 2),
            "percent_used": psutil.virtual_memory().percent,
        },
        "disk": {
            "total_gb": round(disk_usage.total / (1024.0 ** 3), 2),
            "used_gb": round(disk_usage.used / (1024.0 ** 3), 2),
            "percent_used": disk_usage.percent,
        }
    }

def check_for_danger(open_ports, system_info):
    """
    การประเมินความอันตรายอย่างง่าย:
    - Port ที่มีความเสี่ยงเปิดอยู่ (Telnet, FTP)
    - การใช้งาน Disk/RAM สูงเกินเกณฑ์
    """
    danger_level = "LOW"
    warnings = []
    
    # Check 1: Port ที่มีความเสี่ยงสูง (Telnet/FTP)
    if 23 in open_ports or 21 in open_ports:
        danger_level = "MEDIUM"
        warnings.append("CRITICAL: Port 23 (Telnet) หรือ 21 (FTP) เปิดอยู่. ควรเปลี่ยนไปใช้ SSH/SFTP")

    # Check 2: Disk ใช้งานเกิน 90%
    if system_info['disk']['percent_used'] > 90:
        if danger_level == "LOW": danger_level = "MEDIUM"
        warnings.append(f"HIGH: การใช้งาน Disk เกิน 90% ({system_info['disk']['percent_used']}%). เสี่ยงต่อระบบล่ม.")
        
    # Check 3: RAM ใช้งานเกิน 95%
    if system_info['memory']['percent_used'] > 95:
        if danger_level == "LOW": danger_level = "MEDIUM"
        warnings.append(f"HIGH: การใช้งาน RAM สูงถึง {system_info['memory']['percent_used']}%. อาจเกิด OOM (Out of Memory).")

    # Check 4: Running as root (จากไฟล์ service ที่แก้ไขในรอบที่แล้ว)
    if os.getuid() == 0:
        warnings.append("SECURITY NOTE: API รันด้วยสิทธิ์ root (PID 0) ซึ่งมีความเสี่ยงสูง ควรใช้ User เฉพาะกิจที่มีสิทธิ์จำกัด")
        
    if not warnings:
        warnings.append("การสแกนเบื้องต้นไม่พบความอันตรายที่ชัดเจน (No obvious danger detected).")
        
    return {
        "danger_level": danger_level,
        "warnings": warnings
    }

@app.route('/scan', methods=['GET'])
def server_scan():
    """
    Endpoint หลักสำหรับเรียกใช้งานการสแกนระบบทั้งหมด
    """
    # 1. Get System Information
    sys_info = get_system_info()
    
    # 2. Check Open Ports (สแกน Port บน Localhost)
    open_ports = check_open_ports()
    
    # 3. Assess Danger Level
    security_assessment = check_for_danger(open_ports, sys_info)
    
    return jsonify({
        "status": "Scan Complete",
        "system_info": sys_info,
        "port_scan": {
            "open_ports": open_ports,
            "note": "เป็นการสแกนเฉพาะ Port ทั่วไปบน localhost. สำหรับการสแกนภายนอกที่ละเอียดควรใช้เครื่องมือเฉพาะทาง เช่น Nmap."
        },
        "security_assessment": security_assessment
    })

@app.route('/', methods=['GET'])
def status_check():
    """
    Endpoint สถานะพื้นฐาน
    """
    return jsonify({
        "service": "Server Scanner API",
        "status": "Running",
        "endpoint_main": "/scan",
        "access_url": f"http://<IP_ADDRESS>:{PORT}/scan"
    })

if __name__ == '__main__':
    # รันบน 0.0.0.0 เพื่อให้เข้าถึงได้จากภายนอก
    app.run(host='0.0.0.0', port=PORT) 
