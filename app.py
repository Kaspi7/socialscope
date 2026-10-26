import ipaddress
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request

import os
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

@app.route("/health")
def health():
    return {"status": "ok"}, 200
    
def validate_public_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None

        if not parsed.hostname or parsed.username or parsed.password:
            return None

        if parsed.port not in (None, 80, 443):
            return None

        host = parsed.hostname.rstrip(".").lower()

        if host == "localhost" or host.endswith(
            (".localhost", ".local", ".internal")
        ):
            return None

        # Reject literal private, loopback and reserved IP addresses.
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                return None
        except ValueError:
            # Hostname: verify every resolved address is public.
            addresses = socket.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM
            )
            if not addresses:
                return None

            for address in addresses:
                if not ipaddress.ip_address(address[4][0]).is_global:
                    return None

        return parsed
    except (ValueError, OSError):
        return None

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if len(url) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    parsed = validate_public_url(url)
    if not parsed:
        return jsonify({
            "error": "Invalid URL or non-public address blocked."
        }), 400

    try:
        # Avoid automatic redirects to unvalidated destinations.
        with requests.get(
            url,
            timeout=(3, 6),
            headers={"User-Agent": "SocialScope/1.0"},
            allow_redirects=False,
            stream=True
        ) as response:
            if 300 <= response.status_code < 400:
                return jsonify({
                    "error": "Redirect blocked. Enter the final public URL."
                }), 400

            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                return jsonify({
                    "error": "This version analyzes HTML webpages only."
                }), 400

            chunks = []
            total = 0
            for chunk in response.iter_content(8192):
                total += len(chunk)
                if total > 1_000_000:
                    return jsonify({
                        "error": "Page is too large to analyze."
                    }), 400
                chunks.append(chunk)

            html = b"".join(chunks).decode(
                response.encoding or "utf-8", errors="replace"
            )

        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        meta = soup.find("meta", attrs={"name": "description"})
        description = meta.get("content", "")[:1000] if meta else ""

        links = [
            a.get("href", "")[:2048]
            for a in soup.find_all("a", href=True)[:50]
        ]

        return jsonify({
            "url": url,
            "title": title,
            "description": description,
            "links": links
        })

    except (requests.RequestException, OSError, UnicodeError):
        return jsonify({
            "error": "Could not retrieve that page."
        }), 400

@app.route("/debug-files")
def debug_files():
    from pathlib import Path

    root = Path(__file__).parent
    return {
        "app_directory": str(root),
        "root_files": sorted(p.name for p in root.iterdir()),
        "templates_exists": (root / "templates").is_dir(),
        "template_files": (
            sorted(p.name for p in (root / "templates").iterdir())
            if (root / "templates").is_dir()
            else []
        )
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
