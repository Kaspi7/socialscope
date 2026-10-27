
import os
import re
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
CORS(app)

TIMEOUT = 6
COMMON_SUBDOMAINS = [
    "www", "api", "mail", "blog", "dev", "docs", "status"
]

PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/",
    "X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Steam": "https://steamcommunity.com/id/{}/",
    "YouTube": "https://www.youtube.com/@{}",
    "Medium": "https://medium.com/@{}",
}

session = requests.Session()
session.headers.update({
    "User-Agent": "SocialScope/1.0 public-web-security-checker"
})


def normalize_domain(target):
    target = target.strip()

    if not target:
        raise ValueError("Enter a domain.")

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not accepted.")

    if parsed.port not in (None, 80, 443):
        raise ValueError(
            "Custom ports are not supported by this scanner."
        )

    domain = parsed.hostname.rstrip(".").lower()

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    if domain == "localhost" or "." not in domain:
        raise ValueError("Enter a public domain name.")

    try:
        ip = ipaddress.ip_address(domain)
        if not ip.is_global:
            raise ValueError("Private and non-public IPs are blocked.")
        return domain
    except ValueError as exc:
        if "Private and non-public" in str(exc):
            raise

    labels = domain.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9-]+", label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError("Invalid domain name.")

    return domain


def resolve_public_addresses(domain):
    try:
        answers = socket.getaddrinfo(
            domain, 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Domain could not be resolved.")

    addresses = sorted({answer[4][0] for answer in answers})

    if not addresses:
        raise ValueError("No IP addresses found.")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError(
                "Domain resolves to a non-public IP. Scan blocked."
            )

    return addresses


def check_username(username):
    username = username.strip().lstrip("@")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        raise ValueError("Invalid username format.")

    results = []

    for platform, template in PLATFORMS.items():
        url = template.format(username)

        item = {
            "platform": platform,
            "url": url,
            "status": "Unknown",
            "http_status": None
        }

        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True
            )

            item["http_status"] = response.status_code

            if response.status_code == 200:
                item["status"] = "Possible match - verify manually"
            elif response.status_code == 404:
                item["status"] = "HTTP 404 - not found"
            elif response.status_code in (401, 403, 429):
                item["status"] = "Restricted or rate limited"
            else:
                item["status"] = f"HTTP {response.status_code}"

            response.close()

        except requests.RequestException:
            item["status"] = "Request failed or timed out"

        results.append(item)

    return {
        "type": "username",
        "target": username,
        "found_accounts": results,
        "note": (
            "These are candidate profile URLs, not confirmed accounts "
            "or proof that profiles belong to the same person."
        )
    }


def check_tls(domain):
    result = {
        "status": "NOT TESTED",
        "subject": None,
        "issuer": None,
        "expires": None,
        "days_remaining": None,
        "error": None
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, 443), timeout=TIMEOUT
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=domain
            ) as tls_socket:
                cert = tls_socket.getpeercert()

        result["status"] = "PASS"
        result["subject"] = str(cert.get("subject", "Unknown"))
        result["issuer"] = str(cert.get("issuer", "Unknown"))
        result["expires"] = cert.get("notAfter")

        if result["expires"]:
            expiry = datetime.strptime(
                result["expires"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            remaining = (
                expiry - datetime.now(timezone.utc)
            ).days

            result["days_remaining"] = remaining

            if remaining < 0:
                result["status"] = "EXPIRED"
            elif remaining <= 30:
                result["status"] = "EXPIRING SOON"

    except (OSError, ssl.SSLError, ValueError) as exc:
        result["status"] = "REVIEW"
        result["error"] = str(exc)[:250]

    return result


def add_check(checks, name, status, severity, evidence, fix):
    checks.append({
        "name": name,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "recommendation": fix
    })


def check_domain(domain):
    addresses = resolve_public_addresses(domain)
    checks = []
    subdomains = []
    public_files = []
    cookies = []
    server = "Not disclosed"
    headers_report = {}

    # TLS certificate inspection
    tls = check_tls(domain)

    if tls["status"] == "PASS":
        add_check(
            checks, "TLS certificate", "PASS", "Info",
            "Certificate validation succeeded.",
            "Keep the certificate renewed and correctly configured."
        )
    elif tls["status"] == "EXPIRING SOON":
        add_check(
            checks, "TLS certificate", "REVIEW", "Medium",
            f"Certificate expires in {tls['days_remaining']} days.",
            "Renew the certificate before expiry."
        )
    else:
        add_check(
            checks, "TLS certificate", "REVIEW", "High",
            tls["error"] or tls["status"],
            "Check certificate validity, hostname, chain and TLS settings."
        )

    # HTTPS response header review
    response = None
    try:
        response = session.get(
            f"https://{domain}/",
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True
        )

        headers = response.headers
        server = headers.get("Server", "Not disclosed")

        tests = [
            (
                "Content-Security-Policy",
                "Content Security Policy",
                "Medium",
                "Review a restrictive CSP appropriate for the application."
            ),
            (
                "Strict-Transport-Security",
                "HTTP Strict Transport Security",
                "Low",
                "Configure HSTS after confirming HTTPS works throughout."
            ),
            (
                "X-Content-Type-Options",
                "MIME sniffing protection",
                "Low",
                "Consider X-Content-Type-Options: nosniff."
            ),
            (
                "X-Frame-Options",
                "Framing protection",
                "Low",
                "Consider CSP frame-ancestors or X-Frame-Options."
            ),
            (
                "Referrer-Policy",
                "Referrer information policy",
                "Info",
                "Set an appropriate Referrer-Policy for the application."
            ),
            (
                "Permissions-Policy",
                "Browser feature policy",
                "Info",
                "Disable browser features the application does not need."
            )
        ]

        for header, name, severity, recommendation in tests:
            present = bool(headers.get(header))
            headers_report[header] = (
                "Present" if present else "Missing"
            )

            add_check(
                checks,
                name,
                "PASS" if present else "REVIEW",
                "Info" if present else severity,
                f"{header} {'was observed' if present else 'was not observed'}.",
                recommendation
            )

        # Report cookie attributes only; never store cookie values.
        raw_headers = response.raw.headers
        set_cookie = raw_headers.getlist("Set-Cookie")

        for index, raw_cookie in enumerate(set_cookie, 1):
            parts = [
                part.strip() for part in raw_cookie.split(";")
            ]
            attributes = {
                part.split("=", 1)[0].lower()
                for part in parts[1:] if part
            }

            flags = {
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": "samesite" in attributes
            }

            cookies.append({
                "cookie_number": index,
                "flags": flags
            })

            for flag, label in [
                ("secure", "Secure"),
                ("httponly", "HttpOnly"),
                ("samesite", "SameSite")
            ]:
                if not flags[flag]:
                    add_check(
                        checks,
                        f"Cookie {index}: {label}",
                        "REVIEW",
                        "Low",
                        f"Observed cookie lacks the {label} attribute.",
                        f"Review whether this cookie requires {label}."
                    )

        if not set_cookie:
            add_check(
                checks, "Cookie security", "NOT TESTED", "Info",
                "Homepage did not issue a Set-Cookie header.",
                "Cookie security requires observing relevant cookies."
            )

    except requests.RequestException as exc:
        add_check(
            checks, "HTTPS response", "NOT TESTED", "Info",
            str(exc)[:250],
            "Verify the website is reachable and retry."
        )
    finally:
        if response is not None:
            response.close()

    # Plain HTTP redirect check
    response = None
    try:
        response = session.get(
            f"http://{domain}/",
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True
        )

        location = response.headers.get("Location", "")
        redirects = (
            response.status_code in (301, 302, 303, 307, 308)
            and location.lower().startswith("https://")
        )

        add_check(
            checks,
            "HTTP to HTTPS redirect",
            "PASS" if redirects else "REVIEW",
            "Info" if redirects else "Medium",
            f"HTTP status: {response.status_code}; "
            f"HTTPS redirect: {'confirmed' if redirects else 'not confirmed'}.",
            "Redirect HTTP traffic to HTTPS."
        )

    except requests.RequestException as exc:
        add_check(
            checks, "HTTP redirect", "NOT TESTED", "Info",
            str(exc)[:250],
            "Check the HTTP-to-HTTPS redirect manually."
        )
    finally:
        if response is not None:
            response.close()

    # Only inspect standard public metadata paths.
    for path in (
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt"
    ):
        response = None
        try:
            response = session.get(
                f"https://{domain}{path}",
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True
            )

            if response.status_code == 200:
                public_files.append({
                    "path": path,
                    "status": 200
                })

        except requests.RequestException:
            pass
        finally:
            if response is not None:
                response.close()

    # Common subdomain DNS discovery only
    for prefix in COMMON_SUBDOMAINS:
        name = f"{prefix}.{domain}"
        try:
            found = sorted({
                answer[4][0]
                for answer in socket.getaddrinfo(
                    name, 443, type=socket.SOCK_STREAM
                )
            })

            if found and all(
                ipaddress.ip_address(ip).is_global for ip in found
            ):
                subdomains.append({
                    "subdomain": name,
                    "ip": found[0]
                })
        except (socket.gaierror, ValueError):
            continue

    # These counts are preliminary configuration observations.
    summary = {}
    for severity in ("High", "Medium", "Low"):
        summary[severity.lower()] = sum(
            1 for item in checks
            if item["severity"] == severity
            and item["status"] == "REVIEW"
        )

    return {
        "type": "domain",
        "domain": domain,
        "ip_address": addresses[0],
        "all_ip_addresses": addresses,
        "server": server,
        "tls": tls,
        "security_headers": headers_report,
        "security_checks": checks,
        "risk_summary": summary,
        "cookies": cookies,
        "public_files": public_files,
        "subdomains": subdomains,
        "note": (
            "Results are limited observations, not proof of exploitability. "
            "This tool does not test application injection, authentication "
            "bypasses, or stolen credentials."
        )
    }


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("url", "")

    if not isinstance(target, str):
        return jsonify({"error": "Target must be text."}), 400

    target = target.strip()

    if not target or len(target) > 2048:
        return jsonify({"error": "Enter a valid target."}), 400

    try:
        if target.startswith("@"):
            result = check_username(target)
        elif "://" not in target and "/" not in target and "." not in target:
            result = check_username(target)
        else:
            domain = normalize_domain(target)
            result = check_domain(domain)

        return jsonify(result)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("SocialScope scan failed")
        return jsonify({
            "error": "Unexpected scan error. Check Render logs."
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
            
