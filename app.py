from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Enter a public webpage URL."}), 400

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Enter a valid HTTP or HTTPS URL."}), 400

    # Restrict requests to public hostnames to reduce SSRF risk.
    host = parsed.hostname.lower()
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        return jsonify({"error": "Local addresses are not allowed."}), 400

    try:
        response = requests.get(
            url,
            timeout=8,
            headers={"User-Agent": "SocialScope/1.0 (public-page analyzer)"},
            allow_redirects=False
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else "(No title)"
        description = soup.find("meta", attrs={"name": "description"})
        description = description.get("content", "") if description else ""

        links = [
            a.get("href") for a in soup.find_all("a", href=True)
        ][:50]

        return jsonify({
            "url": url,
            "status_code": response.status_code,
            "title": title,
            "description": description,
            "links": links
        })
    except requests.RequestException:
        return jsonify({
            "error": "Could not retrieve that page. It may block automated requests."
        }), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
