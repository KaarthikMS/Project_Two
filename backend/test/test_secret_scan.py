"""
Test Secret Scan - Verifies secret detection regex and entropy logic.
"""

from pathlib import Path
from scanners.secrets_scanner import SecretsScanner

def test_entropy_calculation():
    scanner = SecretsScanner()
    # High entropy string
    assert scanner._shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 4.0
    # Low entropy string
    assert scanner._shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") < 1.0

def test_redaction():
    scanner = SecretsScanner()
    secret = "AKIA1234567890ABCDEF"
    redacted = scanner._redact(secret)
    assert redacted.startswith("AK")
    assert redacted.endswith("EF")
    assert "*" in redacted
    assert secret not in redacted

def test_regex_detection(tmp_path):
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text("AWS_KEY: AKIA1234567890ABCDEF")
    
    scanner = SecretsScanner(use_detect_secrets=False)
    result = scanner.scan(str(tmp_path))
    
    assert result["total"] >= 1
    assert result["vulnerabilities"][0]["secret_type"] == "aws_access_key"
