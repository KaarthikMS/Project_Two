"""
Test Network Scan - Verifies Nmap result parsing.
"""

from scanners.nmap_scanner import NmapScanner

def test_nmap_dangerous_service_detection():
    scanner = NmapScanner()
    # Manually build a host_info for testing extraction logic
    host_info = {
        "host": "1.2.3.4",
        "open_ports": [
            {"port": 23, "service": "telnet"}
        ]
    }
    
    findings = scanner._extract_vulnerabilities(host_info)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "telnet" in findings[0]["description"].lower()

def test_nmap_mock_mode():
    scanner = NmapScanner()
    result = scanner.scan("localhost")
    assert result["scanner"] == "nmap"
    assert len(result["vulnerabilities"]) >= 1
