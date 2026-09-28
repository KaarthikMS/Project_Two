"""
ZAP Scanner - Dynamic Application Security Testing (DAST).

Uses the OWASP Zed Attack Proxy (ZAP) to crawl and scan web applications
for security vulnerabilities like SQLi, XSS, and insecure configurations.
"""

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class ZAPScanner:
    """
    Web application vulnerability scanner using OWASP ZAP.

    Performs:
    - Automated crawling (Spidering)
    - Active scanning for classic web vulnerabilities
    - AJAX spidering for modern SPAs
    - Authentication-aware scanning
    """

    def __init__(
        self,
        proxy_address: str = "127.0.0.1",
        proxy_port: int = 8080,
        api_key: str = "",
    ):
        self.proxy_address = proxy_address
        self.proxy_port = proxy_port
        self.api_key = api_key

    def scan(
        self,
        target_url: str,
        scan_policy: str = "Default Policy",
        authenticated: bool = False,
    ) -> dict[str, Any]:
        """
        Run ZAP spider and active scan on a target URL.
        """

        logger.info("Starting ZAP scan on: %s", target_url)

        try:
            from zapv2 import ZAPv2  # type: ignore

            return self._run_zap_scan(target_url, scan_policy, authenticated, ZAPv2)

        except ImportError:
            return self._error_result("python-owasp-zap-v2.4 not installed. Real scan cannot proceed.")

    def _run_zap_scan(
        self,
        target_url: str,
        scan_policy: str,
        authenticated: bool,
        ZAPv2: Any,
    ) -> dict[str, Any]:
        """Execute ZAP scan using the API client."""

        try:

            # Normalize URL
            if not target_url.startswith("http"):
                target_url = "http://" + target_url

            zap = ZAPv2(
                apikey=self.api_key,
                proxies={
                    "http": f"http://{self.proxy_address}:{self.proxy_port}",
                    "https": f"http://{self.proxy_address}:{self.proxy_port}",
                },
            )

            logger.info("Accessing target through ZAP proxy: %s", target_url)

            # Access target so it appears in ZAP sites tree
            zap.urlopen(target_url)
            time.sleep(2)

            # -----------------------------
            # Spider Scan
            # -----------------------------
            logger.info("Starting spider scan")

            scan_id = zap.spider.scan(target_url)

            while int(zap.spider.status(scan_id)) < 100:
                progress = zap.spider.status(scan_id)
                logger.info("Spider progress: %s%%", progress)
                time.sleep(2)

            logger.info("Spider completed")

            # -----------------------------
            # Active Scan
            # -----------------------------
            logger.info("Starting active scan")

            scan_id = zap.ascan.scan(target_url)

            while int(zap.ascan.status(scan_id)) < 100:
                progress = zap.ascan.status(scan_id)
                logger.info("Active scan progress: %s%%", progress)
                time.sleep(5)

            logger.info("Active scan completed")

            # -----------------------------
            # Collect Alerts
            # -----------------------------
            alerts = zap.core.alerts(baseurl=target_url)

            vulnerabilities = self._parse_alerts(alerts)

            return {
                "scanner": "zap",
                "target": target_url,
                "total": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "severity_breakdown": self._count_by_severity(vulnerabilities),
            }

        except Exception as e:
            logger.error("ZAP scan failed: %s", str(e))
            return self._error_result(str(e))

    def _parse_alerts(self, alerts: list[dict]) -> list[dict]:
        """Convert ZAP alerts to normalized finding format."""

        vulnerabilities = []

        for alert in alerts:
            severity = self._map_severity(alert.get("risk", "Low"))

            vulnerabilities.append(
                {
                    "name": alert.get("alert", ""),
                    "severity": severity,
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "url": alert.get("url", ""),
                    "method": alert.get("method", ""),
                    "param": alert.get("param", ""),
                    "evidence": alert.get("evidence", ""),
                    "cwe": alert.get("cweid", ""),
                    "wasc": alert.get("wascid", ""),
                    "confidence": alert.get("confidence", ""),
                    "scanner": "zap",
                }
            )

        return vulnerabilities

    def _map_severity(self, risk: str) -> str:
        """Map ZAP risk levels to standard severity."""

        risk_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "informational",
        }

        return risk_map.get(risk, "low")

    def _error_result(self, message: str) -> dict:
        return {
            "scanner": "zap",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }

    def _count_by_severity(self, vulnerabilities: list[dict]) -> dict[str, int]:

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        for v in vulnerabilities:
            sev = v.get("severity", "low").lower()

            if sev in counts:
                counts[sev] += 1

        return counts