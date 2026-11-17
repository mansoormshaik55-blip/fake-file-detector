# False File Detector

A Flask web application that inspects uploaded files or downloadable URLs for suspicious file types, executable headers, scripts, and known threat indicators.

## Features

- Upload and analyze files up to 20 MB
- Analyze direct HTTP or HTTPS download links
- Identify file format, category, purpose, and potential risks
- Check extensions against detected file signatures
- Detect suspicious scripts and executable indicators
- Display malware probability, threat classification, findings, and recommendations
- Identify basic website categories and URL reputation indicators

## Requirements

- Python 3.10 or newer
- pip

## Installation

```powershell
cd "C:\path\to\fake-file-detector"
python -m pip install -r requirements.txt
```

## Run the application

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

## Usage

1. Choose a file and select **Scan now**, or enter a direct HTTP/HTTPS download link.
2. Review the returned classification, malware probability, file identification, and security findings.
3. Follow the recommendation and use a trusted antivirus or sandbox for confirmation.

## API

### `POST /api/scan`

Send one uploaded file:

```powershell
curl.exe -F "file=@sample.txt" http://127.0.0.1:5000/api/scan
```

Send a direct URL:

```powershell
curl.exe -F "link=https://example.com/sample.exe" http://127.0.0.1:5000/api/scan
```

The endpoint returns JSON containing the source, risk level, score, malware probability, classification, findings, and content identification.

## Tests

```powershell
python -m pytest
```

## Project structure

```text
app.py                 Flask application and API routes
malware_scanner.py     File and URL analysis logic
templates/index.html   Web interface
static/styles.css      Interface styles
tests/test_scanner.py  Automated tests
requirements.txt       Python dependencies
```

## Security notice

This project is a lightweight, heuristic-based detector. It is not a replacement for antivirus software, malware sandboxes, or professional threat analysis. Low-risk results do not guarantee that a file is safe.

## License

No license is currently specified. Add a license file if you intend others to reuse or redistribute this project.
