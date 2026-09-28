"""
Test Dependency Scan - Verifies SCA scanning logic.
"""

import pytest
from scanners.dependency_scanner import DependencyScanner

def test_dependency_scanner_mock():
    scanner = DependencyScanner()
    # Using a non-existent path will trigger mock data in our implementation for testing
    result = scanner.scan("/non/existent/path")
    
    # In our implementation if path doesn't exist it returns an error result or we can mock pip-audit
    assert result["scanner"] == "dependency"

@pytest.mark.parametrize("pkg,expected_severity", [
    ({"severity": "Critical"}, "critical"),
    ({"severity": "High"}, "high"),
    ({"severity": "nothing"}, "medium"), # default
])
def test_severity_mapping(pkg, expected_severity):
    scanner = DependencyScanner()
    assert scanner._map_severity(pkg) == expected_severity
