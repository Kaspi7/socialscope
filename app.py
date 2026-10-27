import socket
import ssl
import os
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
CORS(app)

# Fallback subdomains list for active footprinting simulation
COMMON_SUBDOMAINS = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'vpn', 'api', 'dev', 'stage']

def evaluate_target(target_url):
    domain = target_url.replace("https://", "").replace("http://", "").split('/')[0].strip()
    report = {
        "domain": domain, 
        "ip_address": "Unknown", 
        "server": "Unknown", 
        "subdomains": [],
        "security_headers": {},
        "ssl": {"issuer": "Unknown", "expires": "Unknown", "status": "Valid"},
        "vulnerabilities": []
    }

    # 1. Host Resolution
    try:
        report["ip_address"] = socket.gethostbyname(domain)
    except Exception:
        return {"error": f"Target host [{domain}] could not be resolved in active DNS registries."}

    # 2. Infrastructure Profiling
    try:
        response = requests.get(f"https://{domain}", timeout=5, headers={"User-Agent": "Mozilla/5.0 OSINT-Collector/2.0"})
        headers = response.headers
        report["server"] = headers.get("Server", "Undetected/Protected")
        
        # Header Evaluations
        headers_to_check = {
            "X-Frame-Options": "Clickjacking Risk",
            "Content-Security-Policy": "XSS Injection Risk",
            "Strict-Transport-Security": "MITM Hacking Risk"
        }
        for header, risk in headers_to_check.items():
            val = headers.get(header)
            report["security_headers"][header] = val if val else "Missing"
            if not val:
                report["vulnerabilities"].append(f"Missing {header} ({risk})")
                
    except Exception:
        report["server"] = "Cloudflare / Firewall Protected"

    # 3. Cryptographic Validation (SSL Check)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x for x in cert.get('issuer', []))
            report["ssl"]["issuer"] = issuer.get('commonName', 'Unknown Authority')
            report["ssl"]["expires"] = cert.get('notAfter', 'Unknown')
    except Exception as e:
        report["ssl"]["status"] = "No Active SSL or Handshake Refused"
        report["vulnerabilities"].append("Cryptographic structure weak or missing HTTPS enforcement.")

    # 4. Fast Subdomain Footprinting Loop
    for sub in COMMON_SUBDOMAINS:
        sub_target = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(sub_target)
            report["subdomains"].append({"subdomain": sub_target, "ip": sub_ip})
        except socket.gaierror:
            continue

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
    # Binds correctly to environment ports dynamically assigned by Render
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
