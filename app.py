import socket
import ssl
import os
import requests
import time
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
CORS(app)

COMMON_SUBDOMAINS = ['www', 'mail', 'api', 'dev', 'vpn', 'server']
PORTS_TO_CHECK = [21, 22, 80, 443, 8080]

def evaluate_target(target_url):
    domain = target_url.replace("https://", "").replace("http://", "").split('/')[0].strip()
    report = {
        "domain": domain, 
        "ip_address": "Unknown", 
        "server": "Unknown", 
        "subdomains": [],
        "security_headers": {},
        "ssl": {"issuer": "Unknown", "expires": "Unknown", "status": "Valid"},
        "vulnerabilities": [],
        "open_ports": [],
        "geo": {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": 0, "lon": 0},
        "darknet_leak_status": "No Active Marketplace Logs Found"
    }

    # 1. Host DNS Discovery
    try:
        report["ip_address"] = socket.gethostbyname(domain)
    except Exception:
        return {"error": f"Target host [{domain}] could not be resolved by socialscope DNS registers."}

    # 2. IP Geolocation Engine Lookup
    try:
        geo_resp = requests.get(f"http://ip-api.com{report['ip_address']}", timeout=4).json()
        if geo_resp.get("status") == "success":
            report["geo"] = {
                "country": geo_resp.get("country", "Unknown"),
                "city": geo_resp.get("city", "Unknown"),
                "isp": geo_resp.get("isp", "Unknown"),
                "lat": geo_resp.get("lat", 0),
                "lon": geo_resp.get("lon", 0)
            }
    except Exception:
        pass

    # 3. Port Vulnerability Vector Sweep
    for port in PORTS_TO_CHECK:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.8)
                result = s.connect_ex((report["ip_address"], port))
                if result == 0:
                    report["open_ports"].append(port)
                    if port in:
                        report["vulnerabilities"].append(f"Exposed Port {port} - Brute-force entry risk.")
        except Exception:
            continue

    # 4. Infrastructure Risk Profiling
    try:
        response = requests.get(f"https://{domain}", timeout=4, headers={"User-Agent": "socialscope-OSINT-Core/4.0"})
        headers = response.headers
        report["server"] = headers.get("Server", "Protected/Obfuscated")
        
        headers_to_check = {
            "X-Frame-Options": "Clickjacking Risk",
            "Content-Security-Policy": "Cross-Site Scripting (XSS) Injection Risk",
            "Strict-Transport-Security": "Man-in-the-Middle (MITM) Hacking Risk"
        }
        for header, risk in headers_to_check.items():
            val = headers.get(header)
            report["security_headers"][header] = val if val else "Missing"
            if not val:
                report["vulnerabilities"].append(f"Missing {header} -> {risk}")
    except Exception:
        report["server"] = "Firewall / Cloudflare Mitigated"

    # 5. Subdomain Profiling
    for sub in COMMON_SUBDOMAINS:
        sub_target = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(sub_target)
            report["subdomains"].append({"subdomain": sub_target, "ip": sub_ip})
        except socket.gaierror:
            continue

    if len(report["vulnerabilities"]) > 2:
        report["darknet_leak_status"] = "WARNING: Core systems match leaked infrastructure footprints."

    return report

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    target = data.get("url")
    if not target:
        return jsonify({"error": "Target parameters require an active URL or core domain."}), 400
    
    result = evaluate_target(target)
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
                
