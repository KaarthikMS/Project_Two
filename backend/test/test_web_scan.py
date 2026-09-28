"""
Test Web Scan - Verifies ZAP and Nuclei integration.
"""

from scanners.zap_scanner import ZAPScanner
from scanners.nuclei_scanner import NucleiScanner

def test_zap_severity_mapping():
    scanner = ZAPScanner()
    assert scanner._map_severity("High") == "high"
    assert scanner._map_severity("Informational") == "informational"

def test_nuclei_parsing():
    scanner = NucleiScanner()
    # Mock nuclei line output
    mock_line = {
        "template-id": "test-vuln",
        "info": {"severity": "critical", "name": "Critical Vuln"},
        "matched-at": "http://example.com"
    }
    parsed = scanner._parse_finding(mock_line)
    assert parsed["severity"] == "critical"
    assert parsed["template_id"] == "test-vuln"
