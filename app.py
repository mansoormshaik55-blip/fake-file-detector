import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from malware_scanner import analyze_file, describe_url_content, identify_url

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def download_url_to_temp_file(url: str, output_dir: str = None) -> str:
    if output_dir is None:
        output_dir = app.config["UPLOAD_FOLDER"]

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS links are supported.")
    if not parsed.netloc:
        raise ValueError("Please provide a valid URL.")

    filename = os.path.basename(parsed.path) or "remote_download.bin"
    safe_name = secure_filename(filename)
    if not safe_name:
        safe_name = "remote_download.bin"

    file_path = os.path.join(output_dir, safe_name)
    stem, ext = os.path.splitext(safe_name)
    counter = 1
    while os.path.exists(file_path):
        file_path = os.path.join(output_dir, f"{stem}_{counter}{ext}")
        counter += 1

    request = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read(2 * 1024 * 1024)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise ValueError(f"Unable to download from the provided link: {exc}") from exc

    with open(file_path, "wb") as handle:
        handle.write(payload)

    return file_path




@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_file():
    file = request.files.get("file")
    link = (request.form.get("link") or "").strip()

    if file and file.filename:
        filename = secure_filename(file.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)
        result = analyze_file(path)
        result["source"] = "uploaded_file"
        return jsonify(result)

    if link:
        try:
            path = download_url_to_temp_file(link, app.config["UPLOAD_FOLDER"])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        result = analyze_file(path)
        result["source"] = "remote_link"
        url_info = identify_url(link)
        website_description = describe_url_content(link, url_info)
        result["brief_summary"] = website_description
        result["summary"] = (
            f"This URL appears to be a {url_info['website_category']} website. {website_description} "
            "The local detector has reviewed the fetched content and reputation indicators, but external reputation services are still required for full verification."
        )
        result["content_identification"] = {
            "website_name": url_info["website_name"],
            "domain": url_info["domain"],
            "website_category": url_info["website_category"],
            "website_purpose": url_info["website_purpose"],
            "url_structure": url_info["url_structure"],
            "https_status": url_info["https_status"],
            "domain_reputation": url_info["domain_reputation"],
            "redirect_information": url_info["redirect_information"],
            "impersonation_detection": url_info["impersonation_detection"],
            "website_description": website_description,
        }
        result["url_identification"] = result["content_identification"]
        return jsonify(result)

    return jsonify({"error": "Please select a file or provide a valid URL."}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
