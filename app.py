import csv
import io
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request, Response
from werkzeug.exceptions import RequestEntityTooLarge

try:
    import dns.resolver
except ImportError:
    dns = None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False

HTTP = requests.Session()
HTTP.headers.update({
    "User-Agent": "SocialScope/1.0 (passive public-information research)"
})
TIMEOUT = 8

PLATFORMS = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Facebook": "https://www.facebook.com/{username}",
    "Discord": "https://discord.com/users/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "X": "https://x.com/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "GitHub": "https://github.com/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Medium": "https://medium.com/@{username}",
}

def result(module, target, summary, findings=None, links=None, metadata=None):
    return {
        "module": module,
        "target": target,
        "summary": summary,
        "findings": findings or [],
        "links": links or [],
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def finding(title, severity, evidence, recommendation, confidence="medium"):
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence
    }

def clean_domain(value):
    value = (value or "").strip()
    if not value or len(value) > 253 or any(c in value for c in "/?#@"):
        raise ValueError("Enter a domain name only, such as example.com.")
    value = value.lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        raise ValueError("Enter the hostname only, without http:// or https://.")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", value):
        raise ValueError("That does not look like a valid public domain.")
    return value

def resolve_public_host(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The domain could not be resolved.")
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise ValueError("No IP addresses were returned for this domain.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("The target resolves to a private or non-public address. This tool only checks public hosts.")
    return addresses

def normalize_public_ip(value):
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        raise ValueError("Enter a valid IPv4 or IPv6 address.")
    if not ip.is_global:
        raise ValueError("Private, loopback, link-local and reserved IP addresses are not supported.")
    return str(ip)

def safe_fetch(url, allow_redirects=False):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only valid HTTP/HTTPS URLs are supported.")
    resolve_public_host(parsed.hostname)
    return HTTP.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects, stream=False)

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "SocialScope", "version": "1.0"})

@app.post("/api/username")
def api_username():
    data = request.get_json(silent=True) or {}
    username = (data.get("target") or "").strip().lstrip("@")
    selected = data.get("platforms") or list(PLATFORMS.keys())
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", username):
        return jsonify({"error": "Use a username containing 1–40 letters, numbers, dots, underscores or hyphens."}), 400
    links = []
    for platform in selected:
        if platform in PLATFORMS:
            links.append({"label": platform, "url": PLATFORMS[platform].format(username=username)})
    if not links:
        return jsonify({"error": "Select at least one supported platform."}), 400
    findings = [finding(
        "Public profile discovery links generated",
        "info",
        "These are direct public profile URLs. A generated link does not prove that an account exists.",
        "Open each result and verify it manually. Respect each platform's terms and privacy settings.",
        "high"
    )]
    return jsonify(result("Username search", username, f"Generated {len(links)} public profile links. Account existence has not been verified.", findings, links,
                          {"platforms_checked": [x["label"] for x in links], "verification": "manual"}))

@app.post("/api/domain")
def api_domain():
    data = request.get_json(silent=True) or {}
    try:
        domain = clean_domain(data.get("target"))
        ips = resolve_public_host(domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    findings, links, meta = [], [], {"resolved_ips": ips}
    records = {}
    try:
        records["A/AAAA"] = ips
    except Exception:
        pass

    if dns:
        for record_type in ("MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=4)
                records[record_type] = [str(x).strip('"') for x in answers][:20]
            except Exception:
                records[record_type] = []
    else:
        records["DNS note"] = ["Install dnspython to enable MX, NS and TXT lookups."]

    links.append({"label": "WHOIS lookup", "url": f"https://lookup.icann.org/en/lookup?name={domain}"})
    links.append({"label": "Certificate transparency", "url": f"https://crt.sh/?q=%25.{domain}"})

    findings.append(finding("DNS resolution completed", "info", ", ".join(ips),
                             "Review the resolved addresses and confirm they belong to the expected hosting provider.", "high"))

    for scheme in ("https", "http"):
        try:
            response = safe_fetch(f"{scheme}://{domain}/")
            headers = {k.lower(): v for k, v in response.headers.items()}
            meta[f"{scheme}_status"] = response.status_code
            meta[f"{scheme}_headers"] = dict(response.headers)
            if scheme == "https":
                security_headers = {
                    "strict-transport-security": ("HSTS header missing", "Configure Strict-Transport-Security after confirming HTTPS works."),
                    "content-security-policy": ("Content Security Policy missing", "Add a restrictive Content-Security-Policy appropriate for the site."),
                    "x-content-type-options": ("X-Content-Type-Options missing", "Set X-Content-Type-Options: nosniff."),
                    "referrer-policy": ("Referrer-Policy missing", "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."),
                    "permissions-policy": ("Permissions-Policy missing", "Set a Permissions-Policy that disables browser features the site does not need.")
                }
                for header, (title, fix) in security_headers.items():
                    if header not in headers:
                        findings.append(finding(title, "low", f"HTTPS response did not include {header}.", fix, "high"))
                if response.url.startswith("http://"):
                    findings.append(finding("HTTPS request ended on HTTP", "high",
                                             "The request was redirected or resolved to an HTTP URL.",
                                             "Force HTTPS and review redirect configuration.", "medium"))
                cookies = response.headers.get("Set-Cookie", "")
                if cookies:
                    lower = cookies.lower()
                    if "secure" not in lower:
                        findings.append(finding("Cookie without Secure attribute observed", "medium",
                                                 "At least one Set-Cookie response did not show the Secure attribute.",
                                                 "Set Secure on cookies that should only travel over HTTPS.", "medium"))
                    if "httponly" not in lower:
                        findings.append(finding("Cookie without HttpOnly attribute observed", "low",
                                                 "At least one Set-Cookie response did not show HttpOnly.",
                                                 "Set HttpOnly on session cookies that do not require JavaScript access.", "medium"))
            break
        except requests.RequestException as exc:
            meta[f"{scheme}_error"] = str(exc)[:180]
        except ValueError as exc:
            meta[f"{scheme}_error"] = str(exc)

    if "https_status" not in meta and "http_status" not in meta:
        findings.append(finding("Website could not be fetched", "info",
                                 "DNS resolved, but the HTTP(S) endpoint did not return a response to this checker.",
                                 "Check whether the site is online and whether it blocks automated requests.", "medium"))

    meta["dns_records"] = records
    return jsonify(result("Domain intelligence", domain, f"Resolved {len(ips)} public address(es) and completed passive HTTP checks.", findings, links, meta))

@app.post("/api/ip")
def api_ip():
    data = request.get_json(silent=True) or {}
    try:
        ip = normalize_public_ip(data.get("target"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        response = HTTP.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
        payload = response.json()
        if not payload.get("success", False):
            return jsonify({"error": payload.get("message", "IP geolocation provider did not return a result.")}), 502
        connection = payload.get("connection") or {}
        info = {
            "ip": ip, "type": payload.get("type"), "continent": payload.get("continent"),
            "country": payload.get("country"), "region": payload.get("region"),
            "city": payload.get("city"), "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"), "isp": connection.get("isp"),
            "organization": connection.get("org"), "asn": connection.get("asn")
        }
        f = finding("Approximate IP geolocation retrieved", "info",
                    f"{info.get('city') or 'Unknown'}, {info.get('country') or 'Unknown'}; ISP: {info.get('isp') or 'Unknown'}.",
                    "Treat IP geolocation as an estimate. It identifies a network endpoint, not a person's exact location.", "medium")
        return jsonify(result("IP intelligence", ip, "Public IP metadata retrieved.", [f], [], info))
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"error": f"Geolocation lookup failed: {str(exc)[:160]}"}), 502

@app.post("/api/email")
def api_email():
    data = request.get_json(silent=True) or {}
    email = (data.get("target") or "").strip()
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400
    domain = email.rsplit("@", 1)[1].lower()
    findings = [finding("Email syntax is valid", "info", "The address matches a basic email syntax check.",
                        "Syntax does not prove that the mailbox exists or belongs to a particular person.", "high")]
    mx = []
    if dns:
        try:
            mx = [str(x.exchange).rstrip(".") for x in dns.resolver.resolve(domain, "MX", lifetime=4)]
        except Exception:
            pass
    if mx:
        findings.append(finding("Mail exchange records found", "info", ", ".join(mx),
                                "MX records indicate that the domain is configured to receive email; they do not verify this mailbox.", "high"))
    else:
        findings.append(finding("No MX records returned", "low", "No MX records were returned by the DNS lookup.",
                                "Check the domain's DNS configuration. Some domains may use fallback mail routing.", "medium"))
    links = [{"label": "Domain breach exposure search", "url": f"https://haveibeenpwned.com/"}]
    return jsonify(result("Email intelligence", email, "Completed syntax and domain mail-record checks. No mailbox verification was attempted.",
                          findings, links, {"domain": domain, "mx_records": mx}))

@app.post("/api/vuln")
def api_vuln():
    # Passive web-configuration audit only; no exploit attempts or intrusive scanning.
    data = request.get_json(silent=True) or {}
    raw = (data.get("target") or "").strip()
    if not data.get("authorized"):
        return jsonify({"error": "Confirm that you own this website or have permission to assess it."}), 403
    try:
        domain = clean_domain(raw)
        ips = resolve_public_host(domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    findings = []
    metadata = {"resolved_ips": ips}
    try:
        response = safe_fetch(f"https://{domain}/")
        headers = {k.lower(): v for k, v in response.headers.items()}
        metadata.update({"status": response.status_code, "server_header": headers.get("server", "not disclosed")})
        checks = [
            ("strict-transport-security", "HSTS not detected", "low", "Enable HSTS after confirming the entire site supports HTTPS."),
            ("content-security-policy", "CSP not detected", "medium", "Deploy a Content-Security-Policy and test it for compatibility."),
            ("x-content-type-options", "MIME-sniffing protection not detected", "low", "Set X-Content-Type-Options: nosniff."),
            ("x-frame-options", "Clickjacking header not detected", "low", "Use X-Frame-Options or CSP frame-ancestors."),
            ("referrer-policy", "Referrer policy not detected", "low", "Set a privacy-appropriate Referrer-Policy.")
        ]
        for header, title, severity, recommendation in checks:
            if header not in headers and not (header == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "").lower()):
                findings.append(finding(title, severity, f"Response did not include {header}.", recommendation, "high"))
        if response.url.startswith("http://"):
            findings.append(finding("HTTPS downgrade observed", "high", "The final URL uses HTTP.",
                                     "Configure HTTPS and redirect all HTTP requests to HTTPS.", "medium"))
        if not findings:
            findings.append(finding("No tested header gaps detected", "info",
                                    "The selected passive header checks did not identify missing controls.",
                                    "This is not a full security assessment and does not establish that the website is secure.", "high"))
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"error": f"Passive check failed: {str(exc)[:180]}"}), 502
    return jsonify(result("Website security audit", domain, f"Completed passive checks on {domain}. No exploit payloads were sent.", findings, [], metadata))

@app.post("/api/social-audit")
def api_social_audit():
    data = request.get_json(silent=True) or {}
    raw = (data.get("target") or "").strip()
    if not data.get("authorized"):
        return jsonify({"error": "Confirm that this is your profile or that you have permission to review it."}), 403
    if len(raw) > 2048:
        return jsonify({"error": "URL is too long."}), 400
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Enter a valid public profile URL."}), 400
    host = parsed.hostname.lower()
    allowed = any(host == p or host.endswith("." + p) for p in [
        "instagram.com", "facebook.com", "discord.com", "reddit.com", "x.com",
        "twitter.com", "tiktok.com", "youtube.com", "github.com", "twitch.tv",
        "pinterest.com", "steamcommunity.com", "medium.com"
    ])
    if not allowed:
        return jsonify({"error": "Use a public profile URL from a supported social platform."}), 400
    findings, metadata = [], {"host": host, "privacy_note": "This audit cannot inspect private account settings or platform-internal security."}
    try:
        response = safe_fetch(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", allow_redirects=False)
        metadata["http_status"] = response.status_code
        metadata["content_type"] = response.headers.get("Content-Type", "unknown")
        if response.status_code == 200:
            findings.append(finding("Public profile endpoint responded", "info",
                                    "The submitted public URL returned HTTP 200. This does not prove account ownership or expose private settings.",
                                    "Review the profile while logged out to understand what the public can see.", "medium"))
        elif response.status_code in (301, 302, 303, 307, 308):
            findings.append(finding("Profile endpoint redirected", "info", f"HTTP {response.status_code} redirect returned.",
                                    "Open the link in a browser and verify the destination manually.", "medium"))
        elif response.status_code in (401, 403, 404):
            findings.append(finding("Profile not publicly readable by this check", "info",
                                    f"The endpoint returned HTTP {response.status_code}. This may reflect login requirements, anti-bot controls, privacy settings or a missing profile.",
                                    "Do not attempt to bypass access controls. Review privacy settings through the account's official app.", "medium"))
        else:
            findings.append(finding("Profile endpoint returned an unusual status", "info", f"HTTP {response.status_code}.",
                                    "Verify manually using the platform's official website or app.", "low"))
    except (requests.RequestException, ValueError) as exc:
        findings.append(finding("Automated profile request failed", "info", str(exc)[:160],
                                "The platform may block automated requests. Review the profile manually.", "low"))
    findings.append(finding("Public-exposure review checklist", "info",
                            "Check visible bio details, contact links, public posts, tagged content, follower visibility and location disclosures.",
                            "Remove unnecessary personal details, review audience controls, disable unwanted location sharing and enable two-factor authentication.", "high"))
    return jsonify(result("Social profile exposure audit", raw, "Completed a limited public-endpoint review. Private settings were not accessed.", findings, [], metadata))

@app.post("/api/export")
def export_results():
    data = request.get_json(silent=True) or {}
    report = data.get("report")
    fmt = data.get("format", "json")
    if not isinstance(report, dict):
        return jsonify({"error": "No report supplied."}), 400
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", str(report.get("target", "report")))[:50] or "report"
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["module", "target", "summary", "severity", "finding", "evidence", "recommendation", "timestamp"])
        write
