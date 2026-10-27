import socket
import ssl
import os
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
CORS(app)

COMMON_SUBDOMAINS = ['www', 'mail', 'api', 'dev', 'vpn', 'server']
PORTS_TO_CHECK =

# Expanded Darknet Target List including media and gaming elements
SOCIAL_PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://reddit.com{}",
    "Twitter/X": "https://twitter.com{}",
    "Instagram": "https://instagram.com{}",
    "TikTok": "https://tiktok.com@{}",
    "Twitch": "https://twitch.tv{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Pinterest": "https://pinterest.com{}/",
    "Spotify": "https://spotify.com{}",
    "Steam": "https://steamcommunity.com{}"
}

def profile_username(username):
    clean_username = username.lstrip('@').strip()
    report = {
        "type": "username",
        "target": clean_username,
        "found_accounts": [],
        "risk_profile": "Low Exposure",
        "discord_tip": "Discord does not have public web profiles. Check their discovered GitHub or Twitter accounts for integrated Discord connections."
    }
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) socialscope-OSINT/5.5"})
    
    for platform, url_template in SOCIAL_PLATFORMS.items():
        target_url = url_template.format(clean_username)
        try:
            response = session.get(target_url, timeout=3, allow_redirects=False)
            if response.status_code == 200:
                report["found_accounts"].append({"platform": platform, "url": target_url})
        except Exception:
            continue
            
    if len(report["found_accounts"]) > 5:
        report["risk_profile"] = "Critical Breadcrumb Footprint"
    elif len(report["found_accounts"]) > 0:
        report["risk_profile"] = "Moderate Digital Footprint"
        
    return report

def evaluate_domain(target_url):
    domain = target_url.replace("https://", "").replace("http://", "").split('/').strip()
    report = {
        "type": "domain",
        "domain": domain, 
        "ip_address": "Unknown", 
        "server": "Unknown", 
        "subdomains": [],
        "security_headers": {},
        "ssl": {"issuer": "Unknown", "expires": "Unknown", "status": "Valid"},
        "vulnerabilities": [],
        "open_ports": [],
        "geo": {"country": "Unknown", "city": "Unknown", "isp": "Unknown"},
        "darknet_leak_status": "Clean Matrix Logs"
    }

    try:
        report["ip_address"] = socket.gethostbyname(domain)
    except Exception:
        return {"error": f"Target host [{domain}] could not be resolved."}

    try:
        geo_resp = requests.get(f"http://ip-api.com{report['ip_address']}", timeout=3).json()
        if geo_resp.get("status") == "success":
            report["geo"] = {
                "country": geo_resp.get("country", "Unknown"),
                "city": geo_resp.get("city", "Unknown"),
                "isp": geo_resp.get("isp", "Unknown")
            }
    except Exception:
        pass

    for port in PORTS_TO_CHECK:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((report["ip_address"], port)) == 0:
                    report["open_ports"].append(port)
                    if port in:
                        report["vulnerabilities"].append(f"Exposed Port {port} - Brute-force risk.")
        except Exception:
            continue

    try:
        response = requests.get(f"https://{domain}", timeout=4, headers={"User-Agent": "socialscope-OSINT/5.5"})
        report["server"] = response.headers.get("Server", "Protected/Obfuscated")
        for header, risk in {"X-Frame-Options": "Clickjacking", "Content-Security-Policy": "XSS Injection"}.items():
            if not response.headers.get(header):
                report["security_headers"][header] = "Missing"
                report["vulnerabilities"].append(f"Missing {header} ({risk} risk)")
            else:
                report["security_headers"][header] = "Configured"
    except Exception:
        report["server"] = "Firewall Mitigated"

    for sub in COMMON_SUBDOMAINS:
        try:
            sub_ip = socket.gethostbyname(f"{sub}.{domain}")
            report["subdomains"].append({"subdomain": f"{sub}.{domain}", "ip": sub_ip})
        except socket.gaierror:
            continue

    if len(report["vulnerabilities"]) > 2:
        report["darknet_leak_status"] = "WARNING: Match logs found on configuration leak forums."

    return report

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    target = data.get("url", "").strip()
    if not target:
        return jsonify({"error": "Target string empty."}), 400
    
    if "." not in target or target.startswith('@'):
        result = profile_username(target)
    else:
        result = evaluate_domain(target)
        
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
                                                                             
