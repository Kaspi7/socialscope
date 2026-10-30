import ipaddress
import json
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False
TIMEOUT = 8
USER_AGENT = "SocialScope/1.0 (public security assessment)"


PLATFORMS = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Facebook": "https://www.facebook.com/{username}",
    "X": "https://x.com/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "GitHub": "https://github.com/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Discord (public search)": "https://www.google.com/search?q=site%3Adiscord.com%2Fusers+%22{username}%22",
    "Telegram": "https://t.me/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}/",
    "Snapchat": "https://www.snapchat.com/add/{username}",
    "Threads": "https://www.threads.net/@{username}",
}


def now():
    return datetime.now(timezone.utc).isoformat()

def clean_username(value):
    value = str(value or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        raise ValueError("Enter a username using letters, numbers, dots, underscores, or hyphens.")
    return value

def normalize_domain(value):
    value = str(value or "").strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        value = value.split("/")[0].split(":")[0]
    value = value.strip(".").lower()
    if not value or len(value) > 253 or "." not in value:
        raise ValueError("Enter a valid domain name, such as example.com.")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("The domain format is invalid.")
    return value

def safe_public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        raise ValueError("Enter a valid IPv4 or IPv6 address.")
    if not ip.is_global:
        raise ValueError("Use a public IP address.")
    return str(ip)

def get_url(url):
    headers = {"User-Agent": USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        return response
    except requests.RequestException as exc:
        return {"error": str(exc)[:220]}

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": "SocialScope", "time": now()})

@app.post("/api/username-search")
def username_search():
    data = request.get_json(silent=True) or {}
    try:
        username = clean_username(data.get("username"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    results = []
    for platform, template in PLATFORMS.items():
        url = template.format(username=username)
        result = get_url(url)
        if isinstance(result, dict):
            results.append({"platform": platform, "url": url, "status": "unreachable", "http_status": None})
            continue
        code = result.status_code
        # HTTP status is only a reachability clue, not proof of account existence.
        state = "reachable" if code < 400 else "not_confirmed"
        results.append({
            "platform": platform,
            "url": url,
            "status": state,
            "http_status": code,
            "note": "HTTP status is a reachability signal; platforms may block automated requests or return generic pages."
        })
    return jsonify({"username": username, "checked_at": now(), "results": results})

@app.post("/api/domain-scan")
def domain_scan():
    data = request.get_json(silent=True) or {}
    try:
        domain = normalize_domain(data.get("domain"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    findings = []
    result = {"domain": domain, "checked_at": now(), "dns": {}, "https": {}, "findings": findings}
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in infos})
        result["dns"]["addresses"] = ips
        findings.append({"severity": "info", "title": "DNS resolution succeeded", "detail": f"Resolved to {len(ips)} address(es)."})
    except socket.gaierror:
        result["dns"]["addresses"] = []
        findings.append({"severity": "high", "title": "DNS resolution failed", "detail": "The domain did not resolve from this server."})
        return jsonify(result)

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        response = get_url(url)
        if isinstance(response, dict):
            result[scheme] = {"reachable": False, "error": response["error"]}
            continue
        headers = {k.lower(): v for k, v in response.headers.items()}
        result[scheme] = {
            "reachable": True,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": {
                "strict-transport-security": headers.get("strict-transport-security"),
                "content-security-policy": headers.get("content-security-policy"),
                "x-content-type-options": headers.get("x-content-type-options"),
                "x-frame-options": headers.get("x-frame-options"),
                "referrer-policy": headers.get("referrer-policy"),
                "permissions-policy": headers.get("permissions-policy"),
            },
            "cookies": response.headers.get("Set-Cookie", "")
        }
        if scheme == "https":
            checks = [
                ("strict-transport-security", "HSTS header missing", "medium"),
                ("content-security-policy", "Content-Security-Policy header missing", "low"),
                ("x-content-type-options", "X-Content-Type-Options header missing", "low"),
                ("referrer-policy", "Referrer-Policy header missing", "low"),
            ]
            for header, title, severity in checks:
                if not headers.get(header):
                    findings.append({"severity": severity, "title": title, "detail": f"The HTTPS response did not include {header}."})
            cookie_header = response.headers.get("Set-Cookie", "")
            if cookie_header:
                lower = cookie_header.lower()
                if "secure" not in lower:
                    findings.append({"severity": "medium", "title": "Cookie Secure attribute may be missing", "detail": "At least one Set-Cookie response header was observed without a Secure attribute. Review each cookie individually."})
                if "httponly" not in lower:
                    findings.append({"severity": "low", "title": "Cookie HttpOnly attribute may be missing", "detail": "At least one Set-Cookie response header was observed without an HttpOnly attribute. Review each cookie individually."})
        if scheme == "http" and response.status_code < 400 and not str(response.url).startswith("https://"):
            findings.append({"severity": "medium", "title": "HTTP endpoint did not visibly redirect to HTTPS", "detail": "The HTTP request ended without an HTTPS final URL."})

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result["tls"] = {
                    "version": tls.version(),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                }
                findings.append({"severity": "info", "title": "TLS handshake succeeded", "detail": f"Negotiated {tls.version()}."})
    except Exception as exc:
        result["tls"] = {"error": str(exc)[:180]}
        findings.append({"severity": "high", "title": "TLS connection could not be verified", "detail": "The scanner could not complete a verified TLS connection on port 443."})

    result["summary"] = {
        "findings": len([f for f in findings if f["severity"] != "info"]),
        "high": sum(f["severity"] == "high" for f in findings),
        "medium": sum(f["severity"] == "medium" for f in findings),
        "low": sum(f["severity"] == "low" for f in findings),
    }
    return jsonify(result)

@app.post("/api/ip-lookup")
def ip_lookup():
    data = request.get_json(silent=True) or {}
    try:
        ip = safe_public_ip(data.get("ip"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        response = requests.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        payload = response.json()
        if not payload.get("success", True):
            return jsonify({"error": payload.get("message", "IP lookup failed.")}), 502
        return jsonify({
            "ip": ip,
            "checked_at": now(),
            "country": payload.get("country"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "connection": payload.get("connection", {}),
            "timezone": payload.get("timezone", {}),
            "note": "IP geolocation is approximate and does not identify a person's exact location."
        })
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"error": f"IP lookup failed: {str(exc)[:180]}"}), 502

@app.post("/api/email-check")
def email_check():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400
    domain = email.rsplit("@", 1)[1].lower()
    result = {"email": email, "domain": domain, "checked_at": now(), "syntax_valid": True, "dns": [], "note": "This does not confirm mailbox existence or whether the address has been breached."}
    try:
        import dns.resolver
        for record_type in ("MX", "A", "AAAA"):
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=TIMEOUT)
                result["dns"].append({"type": record_type, "records": [str(x) for x in answers]})
            except Exception:
                result["dns"].append({"type": record_type, "records": []})
    except ImportError:
        try:
            result["dns"].append({"type": "A", "records": sorted({x[4][0] for x in socket.getaddrinfo(domain, None)})})
        except Exception:
            result["dns"].append({"type": "A", "records": []})
    return jsonify(result)

@app.post("/api/social-audit")
def social_audit():
    data = request.get_json(silent=True) or {}
    platform = str(data.get("platform") or "").strip().lower()
    checks = data.get("checks") or {}
    if platform not in {"instagram", "facebook", "discord", "reddit", "x", "tiktok", "youtube", "github", "own_app"}:
        return jsonify({"error": "Choose a supported platform."}), 400
    checklist = {
        "privacy_reviewed": "Reviewed profile visibility and discoverability settings",
        "mfa_enabled": "Multi-factor authentication enabled",
        "recovery_secure": "Recovery email and phone are current and protected",
        "sessions_reviewed": "Reviewed active sessions and signed out unknown devices",
        "connected_apps_reviewed": "Reviewed and removed unneeded connected apps / OAuth grants",
        "unique_password": "Unique password stored in a password manager",
        "alerts_enabled": "Login/security alerts enabled where available",
        "public_info_minimized": "Reduced unnecessary public personal information",
    }
    results = []
    for key, label in checklist.items():
        checked = bool(checks.get(key))
        results.append({"id": key, "label": label, "status": "pass" if checked else "review", "detail": "Marked complete by the user." if checked else "Not confirmed; review this setting in the official app or account settings."})
    completed = sum(item["status"] == "pass" for item in results)
    return jsonify({
        "platform": platform,
        "checked_at": now(),
        "type": "user-guided account security checklist",
        "completed": completed,
        "total": len(results),
        "results": results,
        "note": "This is a user-guided checklist, not a direct test of the platform's internal systems."
    })

@app.post("/api/proxy-check")
def proxy_check():
    data = request.get_json(silent=True) or {}
    proxy = str(data.get("proxy") or "").strip()
    if not proxy:
        return jsonify({"error": "Enter a proxy URL."}), 400
    parsed = urlparse(proxy)
    if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname or not parsed.port:
        return jsonify({"error": "Use a proxy URL with scheme, host, and port, such as http://host:port."}), 400
    # Proxy credentials are accepted only in the request and are never written to disk or logged.
    try:
        response = requests.get(
            "https://ipwho.is/",
            proxies={"http": proxy, "https": proxy},
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT}
        )
        payload = response.json()
        if response.status_code >= 400 or not payload.get("success", True):
            return jsonify({"connected": False, "error": "The proxy test endpoint did not return a successful result."}), 502
        return jsonify({
            "connected": True,
            "observed_ip": payload.get("ip"),
            "country": payload.get("country"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "checked_at": now(),
            "note": "This tests a request made by the server through the configured proxy; it does not route your phone or browser traffic through it."
        })
    except requests.RequestException as exc:
        return jsonify({"connected": False, "error": f"Proxy connection failed: {str(exc)[:180]}"}), 502

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413

@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "Internal server error."}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
