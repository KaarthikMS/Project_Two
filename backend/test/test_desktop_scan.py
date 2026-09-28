"""
Test Desktop Binary Scan - Verifies binary hardening checks and CAPA integration.
"""

import pytest
from unittest.mock import patch, MagicMock
from backend.scanners.desktop_scanner import DesktopBinaryScanner
from pathlib import Path

def test_detect_platform(tmp_path):
    scanner = DesktopBinaryScanner()
    
    exe_file = tmp_path / "test.exe"
    exe_file.write_text("fake exe")
    assert scanner._detect_platform(exe_file) == "windows"
    
    dylib_file = tmp_path / "test.dylib"
    dylib_file.write_text("fake dylib")
    assert scanner._detect_platform(dylib_file) == "macos"

def test_capa_severity_mapping():
    scanner = DesktopBinaryScanner()
    
    # Critical rule
    meta_crit = {"namespace": "malware/inject"}
    assert scanner._capa_severity(meta_crit, "Inject Shellcode") == "critical"
    
    # High rule
    meta_high = {"namespace": "evasion/anti-debug"}
    assert scanner._capa_severity(meta_high, "Check for Debugger") == "high"
    
    # Low rule
    meta_low = {"namespace": "common/filesystem"}
    assert scanner._capa_severity(meta_low, "Open File") == "low"

@patch("subprocess.run")
def test_capa_execution_mock(mock_run, tmp_path):
    scanner = DesktopBinaryScanner(capa_path="/mock/capa")
    
    binary_file = tmp_path / "malver.exe"
    binary_file.write_text("malicious content")
    
    # Mock CAPA JSON output
    mock_output = MagicMock()
    mock_output.stdout = """
    {
        "rules": {
            "Inject DLL": {
                "meta": {"namespace": "malware/inject", "description": "Injects DLL into process", "scope": "file"}
            }
        }
    }
    """
    mock_output.returncode = 0
    mock_run.return_value = mock_output
    
    findings = scanner._run_capa(binary_file)
    
    assert len(findings) == 1
    assert findings[0]["name"] == "Inject DLL"
    assert findings[0]["severity"] == "critical"

def test_hardening_finding_structure():
    scanner = DesktopBinaryScanner()
    finding = scanner._hardening_finding(
        "No NX", "high", "/path/to/bin", "Missing protection", "CWE-121", "Fix it"
    )
    assert finding["scanner"] == "desktop_binary"
    assert finding["category"] == "binary_hardening"
    assert finding["severity"] == "high"
