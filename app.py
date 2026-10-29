
import ipaddress
import re
import socket
from urllib.parse import quote, urlparse

import dns.resolver
import requests
from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

TIMEOUT = 8

PLATFORMS = {
    "Instagram": "https://www.google.com/search?q=site%3Ainstagram.com%2F+{}",
    "Facebook": "https://www.google.com/search?q=site%3Afacebook.com+{}",
    "Discord": "https://www.google.com/search?q=site%3Adiscord.com+{}",
    "TikTok": "https://www.google.com/search?q=site%3Atiktok.com%2F%40{}",
    "Reddit": "https://www.google.com/search?q=site%3Areddit.com%2Fu%2F{}",
    "GitHub": "https://github.com/{}",
    "YouTube": "https://www.youtube.com/results?search_query={}",
    "X": "https://x.com/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Telegram": "https://t.me/{}",
    "LinkedIn": "https://www.google.com/search?q=site%3Alinkedin.com%2Fin%2F+{}",
}


def valid_domain(value):
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "://" in value:
        return None

    if value.startswith("*.") or "/" in value or "@" in value:
        return None

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = value.split(".")
    if len(labels) < 2:
        return None

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        ):
            return None

    return value


def resolve_public_host(host):
    """Return public IP addresses only; reject private and special-use targets."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            addresses = list({
                ipaddress.ip_address(item[4][0])
                for item in records
            })
        except (socket.gaierror, OSError, ValueError):
            return None

    if not addresses:
        return None

    if any(not address.is_global for address in addresses):
        return None

    return addresses


def clean_target(value):
    """Accept a hostname or HTTP(S) URL and return a validated public hostname."""
    value = (value or "").strip()
    if not value or len(value) > 2048:
        return None

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            return None
        if parsed.username or parsed.password:
            return None
        if not parsed.hostname:
            return None

        host = parsed.hostname.rstrip(".").lower()
        domain = valid_domain(host)

        try:
            ipaddress.ip_address(host)
            domain = host
        except ValueError:
            pass

        if not domain:
            return None

        port = parsed.port
        if port is not None and port not in (80, 443):
            return None

        if not resolve_public_host(domain):
            return None

        return domain
    except (ValueError, UnicodeError):
        return None


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/account")
def account_search():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lstrip("@")

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,50}", username):
        return jsonify({"error": "Invalid username"}), 400

    encoded = quote(username, safe="")
    results = {
        platform: template.format(encoded)
        for platform, template in PLATFORMS.items()
    }

    return jsonify({
        "type": "account",
        "query": username,
        "results": results
    })


@app.post("/api/email")
def email_search():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()

    if len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return jsonify({"error": "Invalid email format"}), 400

    domain = email.rsplit("@", 1)[1].lower()
    result = {
        "type": "email",
        "email": email,
        "domain": domain,
        "format_valid": True,
        "mx_records": [],
        "mx_check": "unavailable"
    }

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        result["mx_records"] = sorted(
            [str(answer.exchange).rstrip(".") for answer in answers]
        )
        result["mx_check"] = "found" if result["mx_records"] else "none"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result["mx_check"] = "none"
    except Exception:
        result["mx_check"] = "unavailable"

    return jsonify(result)


@app.post("/api/domain")
def domain_search():
    data = request.get_json(silent=True) or {}
    domain = valid_domain(str(data.get("domain", "")))

    if not domain:
        return jsonify({"error": "Invalid domain"}), 400

    result = {
        "type": "domain",
        "domain": domain,
        "records": {}
    }

    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(
                domain, record_type, lifetime=TIMEOUT
            )
            if record_type == "TXT":
                values = [
                    b"".join(answer.strings).decode("utf-8", "replace")
                    for answer in answers
                ]
            elif record_type == "MX":
                values = [
                    f"{answer.preference} {str(answer.exchange).rstrip('.')}"
                    for answer in answers
                ]
            else:
                values = [str(answer).rstrip(".") for answer in answers]

            result["records"][record_type] = values
        except Exception:
            result["records"][record_type] = []

    return jsonify(result)


@app.post("/api/geolocate")
def geolocate():
    data = request.get_json(silent=True) or {}
    raw_ip = str(data.get("ip", "")).strip()

    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    if not address.is_global:
        return jsonify({"error": "A public IP address is required"}), 400

    try:
        response = requests.get(
            f"http://ip-api.com/json/{address}",
            params={
                "fields": "status,message,country,regionName,city,isp,org,as,lat,lon,query"
            },
            timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return jsonify({"error": data.get("message", "Lookup failed")}), 502

        return jsonify({
            "type": "geolocation",
            "ip": data.get("query"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon")
        })
    except requests.RequestException:
        return jsonify({"error": "Geolocation service unavailable"}), 502


@app.post("/api/vulnerability")
def vulnerability_check():
    data = request.get_json(silent=True) or {}
    host = clean_target(str(data.get("url", "")))

    if not host:
        return jsonify({"error": "Invalid or non-public hostname"}), 400

    findings = []
    checked = None
    errors = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "SocialScope-Security-Check/1.0"}
            )
            checked = {
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
            response.close()
            break
        except requests.RequestException:
            errors.append(scheme)

    if checked is None:
        return jsonify({
            "error": "Could not connect to the public website",
            "failed_attempts": errors
        }), 502

    headers = {
        key.lower(): value
        for key, value in checked["headers"].items()
    }

    checks = [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy", "Content Security Policy"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options"),
        ("referrer-policy", "Referrer-Policy")
    ]

    for key, label in checks:
        if key not in headers:
            findings.append({
                "check": label,
                "status": "missing",
                "severity": "low"
            })

    if checked["url"].startswith("http://"):
        findings.append({
            "check": "HTTPS",
            "status": "HTTP endpoint responded without HTTPS",
            "severity": "medium"
        })

    return jsonify({
        "type": "security_headers",
        "target": host,
        "url_checked": checked["url"],
        "http_status": checked["status_code"],
        "findings": findings,
        "finding_count": len(findings)
    })


@app.post("/api/export")
def export_json():
    data = request.get_json(silent=True) or {}
    import json

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        payload,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="socialscope-export.json"'
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=False)
    
