"""
Nuclei Scanner - Template-based vulnerability scanner.

Wraps the nuclei engine (ProjectDiscovery) to scan web applications
for known vulnerabilities, misconfigurations, and CVEs using
advanced YAML-based templates.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Vulnerability scanner using Nuclei.

    Performs:
    - Web vulnerability detection
    - API security scanning
    - Cloud misconfiguration scanning (via network)
    - CVE detection (over 7000+ templates)
    """

    def __init__(self, timeout: int = 600, severity_filter: str = "critical,high,medium"):
        self.timeout = timeout
        self.severity_filter = severity_filter

    def scan(self, target_url: str) -> dict[str, Any]:
        """
        Run Nuclei scan on a target URL.

        Args:
            target_url: URL to scan

        Returns:
            Dict containing vulnerabilities and metadata
        """
        logger.info("Starting Nuclei scan on: %s", target_url)

        try:
            return self._run_nuclei(target_url)
        except Exception as e:
            logger.error("Nuclei scan failed: %s", str(e))
            return self._error_result(str(e))

    def _run_nuclei(self, target_url: str) -> dict[str, Any]:
        """Execute Nuclei CLI and parse output."""
        # Create a temporary file for results
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        cmd = [
            "nuclei",
            "-target", target_url,
            "-json-export", output_file,
            "-severity", self.severity_filter,
            "-timeout", "5",  # connection timeout
            "-stats",
            "-no-interact",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Nuclei might not produce output if no findings
            vulnerabilities = []
            if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
                with open(output_file, "r") as f:
                    # Nuclei output is line-delimited JSON
                    for line in f:
                        if line.strip():
                            vulnerabilities.append(self._parse_finding(json.loads(line)))
            
            # Clean up
            if Path(output_file).exists():
                Path(output_file).unlink()

            return {
                "scanner": "nuclei",
                "target": target_url,
                "total": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "severity_breakdown": self._count_by_severity(vulnerabilities),
            }

        except FileNotFoundError:
            if Path(output_file).exists():
                Path(output_file).unlink()
            return self._error_result("Nuclei engine not found. Ensure it is installed and in PATH.")
        except subprocess.TimeoutExpired:
            logger.error("Nuclei timed out on %s", target_url)
            if Path(output_file).exists():
                Path(output_file).unlink()
            return self._error_result("Scan timed out")

    def _parse_finding(self, item: dict) -> dict:
        """Parse raw Nuclei output into normalized finding."""
        info = item.get("info", {})
        return {
            "template_id": item.get("template-id", ""),
            "severity": info.get("severity", "low").lower(),
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "matched_at": item.get("matched-at", ""),
            "type": item.get("type", ""),
            "cwe": info.get("classification", {}).get("cwe-id", []),
            "remediation": info.get("remediation", ""),
            "reference": info.get("reference", []),
            "curl_command": item.get("curl-command", ""),
            "scanner": "nuclei",
        }


    def _count_by_severity(self, vulnerabilities: list[dict]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _error_result(self, message: str) -> dict:
        return {
            "scanner": "nuclei",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }
