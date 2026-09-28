"""
Test MobSF Scan - Verifies mobile security analysis logic and API normalization.
"""

import pytest
from unittest.mock import patch, MagicMock
from backend.scanners.mobsf_scanner import MobSFScanner
from pathlib import Path

def test_mobsf_severity_mapping():
    scanner = MobSFScanner()
    assert scanner._map_severity("high") == "high"
    assert scanner._map_severity("warning") == "medium"
    assert scanner._map_severity("info") == "informational"
    assert scanner._map_severity("unknown") == "unknown"

def test_mobsf_count_by_severity():
    scanner = MobSFScanner()
    vulns = [
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "medium"},
        {"severity": "low"}
    ]
    counts = scanner._count_by_severity(vulns)
    assert counts["high"] == 1
    assert counts["medium"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0

@patch("requests.post")
def test_mobsf_scan_single_mock(mock_post, tmp_path):
    # Mock APK file
    apk_file = tmp_path / "test.apk"
    apk_file.write_text("fake apk content")
    
    scanner = MobSFScanner(api_key="test_key")
    
    # 1. Mock Upload Response
    mock_upload = MagicMock()
    mock_upload.json.return_value = {"hash": "abc123", "scan_type": "apk"}
    mock_upload.status_code = 200
    
    # 2. Mock Scan Response
    mock_scan = MagicMock()
    mock_scan.json.return_value = {"status": "success"}
    mock_scan.status_code = 200
    
    # 3. Mock Report Response
    mock_report = MagicMock()
    mock_report.json.return_value = {
        "app_name": "TestApp",
        "package_name": "com.test.app",
        "code_analysis": {
            "findings": {
                "Insecure Crypto": {
                    "rule1": {"metadata": {"severity": "high", "description": "Weak encryption used"}}
                }
            }
        },
        "manifest_analysis": [
            {"title": "Debug Enabled", "severity": "high", "description": "App is debuggable"}
        ]
    }
    mock_report.status_code = 200
    
    mock_post.side_effect = [mock_upload, mock_scan, mock_report]
    
    result = scanner._scan_single(apk_file)
    
    assert result["scanner"] == "mobsf"
    assert result["app_name"] == "TestApp"
    assert result["total"] == 2
    assert result["severity_breakdown"]["high"] == 2
    assert "Weak encryption" in result["vulnerabilities"][0]["description"]
