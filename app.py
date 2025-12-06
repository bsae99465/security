import nmap
import json
import psutil # For checking resources and processes
import platform
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
# Professional practice: Use a dedicated error for Nmap installation issue
class NmapNotInstalledError(Exception):
    pass

def run_nmap_scan(target):
    """
    Runs a detailed Nmap scan for port, service, and basic security headers.
    """
    try:
        nm = nmap.PortScanner()
        # Arguments: -sV (Service version detection), -T4 (Timing), --script (Security headers)
        arguments = '-sV -T4 --script http-headers'
        nm.scan(target, arguments=arguments)
    except nmap.nmap.PortScannerError as e:
        # Check if error is due to missing Nmap command
        if 'nmap program was not found' in str(e):
            raise NmapNotInstalledError("Nmap command not found. Please ensure it's installed.")
        raise Exception(f"Nmap scan failed: {e}")
    except Exception as e:
        raise e
        
    results = {}
    for host in nm.all_hosts():
        # Get host state (up/down)
        results['status'] = nm[host].state
        
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
        if 'hostscript' in nm[host]:
             for script in nm[host]['hostscript']:
                if script['id'] == 'http-headers':
                    results['security_headers'] = script['output'].strip().split('\n')

    return results

def check_local_security_and_user():
    """
    3, 5, 6. Checks for running users, resource usage, and suspicious processes (Agent role).
    """
    checks = {}
    
    # 2. Check current logged-in users and uptime (Basic User Check)
    if platform.system() == "Linux":
        try:
            # Get users logged in (Professional: use `who` or `w` command safely)
            output = subprocess.check_output(['w', '-hs']).decode('utf-8').split('\n')
            logged_in_users = [line.strip() for line in output if line.strip()]
            checks['logged_in_users'] = logged_in_users
        except:
             checks['logged_in_users'] = ["Error retrieving user info"]
    
    # 3. Check for suspicious high CPU usage (Potential Cryptominer Check)
    high_cpu_processes = []
    # Set a threshold, e.g., anything over 50% CPU
    CPU_THRESHOLD = 50 
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        if proc.info['cpu_percent'] > CPU_THRESHOLD:
             # Professional: Check for known miner names like 'xmrig', 'cpuminer', etc.
             is_suspicious = "Potential Miner" if "miner" in proc.info['name'].lower() else "High Usage"
             
             high_cpu_processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'cpu_percent': proc.info['cpu_percent'],
                'type': is_suspicious
             })
             
    checks['high_cpu_processes'] = high_cpu_processes
    
    # 6. Basic check for files (You would replace this with a proper integrity/malware check)
    checks['security_note'] = "ไฟล์อันตรายต้องตรวจสอบด้วย Agent/Tools เช่น ClamAV และ Hash Integrity Check"

    return checks

@app.route('/api/scan/external', methods=['POST'])
def handle_external_scan():
    """
    Endpoint for external scans (Port, Service, Nmap Security).
    """
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "Target IP/Domain is required"}), 400
    
    try:
        results = run_nmap_scan(target)
        return jsonify(results)
    except NmapNotInstalledError as e:
        # 500 Internal Server Error is appropriate if a dependency is missing
        return jsonify({"error": str(e), "suggestion": "Run the install script again to ensure all dependencies are met."}), 500
    except Exception as e:
        app.logger.error(f"Scan failed for {target}: {e}")
        return jsonify({"error": "Failed to complete scan.", "details": str(e)}), 500

@app.route('/api/scan/internal', methods=['GET'])
def handle_internal_scan():
    """
    Endpoint for local checks (Users, Processes, Crypto-mining).
    """
    try:
        results = check_local_security_and_user()
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Internal check failed: {e}")
        return jsonify({"error": "Failed to complete internal checks.", "details": str(e)}), 500

if __name__ == '__main__':
    # Professional practice: Do not run with debug=True or on 0.0.0.0 directly in production
    # Use a proper WSGI server (Gunicorn/uWSGI) proxy (Nginx) for production.
    # For development/quick setup, this is sufficient.
    app.run(host='0.0.0.0', port=8989) 
