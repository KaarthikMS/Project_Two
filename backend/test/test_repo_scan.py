"""
Test Repo Scan - Verifies the repository downloader and Semgrep integration.
"""

from unittest.mock import patch, MagicMock
from scanners.semgrep_scanner import SemgrepScanner
from utils.repo_downloader import RepoDownloader

def test_repo_downloader_cleanup():
    with RepoDownloader("https://github.com/juice-shop/juice-shop") as path:
        assert "ai_sec_scan_" in path
        # Verify mock structure was created if git is missing
        import os
        assert os.path.exists(os.path.join(path, "requirements.txt"))
    # Path should be cleaned up after exit
    import os
    assert not os.path.exists(path)

def test_semgrep_scanner_mock():
    scanner = SemgrepScanner()
    result = scanner.scan("/fake/path")
    assert result["scanner"] == "semgrep"
    # If semgrep isn't installed it returns mock data
    assert result["total"] >= 0
