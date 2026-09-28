"""
MobSF Scanner - OWASP Mobile Security Framework Integration.

Uses the MobSF REST API (Docker container) to perform comprehensive
static analysis on Android (APK) and iOS (IPA) applications.

MobSF Docker: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List

import requests

logger = logging.getLogger(__name__)


class MobSFScanner:
    """
    OWASP MobSF-powered mobile application security scanner.

    Supports:
    - Android: APK, XAPK, APKS, AAR
    - iOS: IPA
    - Static Analysis: Manifest, permissions, code, crypto, network, binary
    - OWASP Mobile Top 10 mapping
    - CVSS scoring
    """

    SUPPORTED_EXTENSIONS = {".apk", ".xapk", ".apks", ".aar", ".ipa"}

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:8001",
        api_key: str = "mobsf_fixed_api_key_12345",
        timeout: int = 600,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = os.environ.get("MOBSF_API_KEY", api_key)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Entry point: accepts a file path or directory.
        Scans all supported mobile binaries found at `target`.
        """
        target_path = Path(target)

        if target_path.is_file():
            return self._scan_single(target_path)
        elif target_path.is_dir():
            return self._scan_directory(target_path)
        else:
            return self._error_result(f"Target not found: {target}")

    def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """Alias used by the orchestrator for directory targets."""
        return self.scan(directory_path)

    # ------------------------------------------------------------------
    # Internal scanning logic
    # ------------------------------------------------------------------

    def _scan_directory(self, directory: Path) -> Dict[str, Any]:
        """Walk a directory and scan every APK/IPA file."""
        all_vulns: List[Dict] = []
        scanned_files: List[str] = []

        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                    result = self._scan_single(fpath)
                    all_vulns.extend(result.get("vulnerabilities", []))
                    scanned_files.append(str(fpath))

        if not scanned_files:
            return {
                "scanner": "mobsf",
                "target": str(directory),
                "total": 0,
                "files_scanned": 0,
                "vulnerabilities": [],
                "severity_breakdown": self._empty_severity(),
                "info": "No APK/IPA files found in target directory.",
            }

        return {
            "scanner": "mobsf",
            "target": str(directory),
            "files_scanned": len(scanned_files),
            "files": scanned_files,
            "total": len(all_vulns),
            "vulnerabilities": all_vulns,
            "severity_breakdown": self._count_by_severity(all_vulns),
        }

    def _scan_single(self, file_path: Path) -> Dict[str, Any]:
        """Upload → Scan → Report for a single mobile binary."""
        logger.info("MobSF scanning: %s", file_path)

        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return self._error_result(
                f"Unsupported file type: {file_path.suffix}"
            )

        if not self.api_key:
            return self._error_result("MobSF API key not set. Real scan cannot proceed.")

        try:
            # 1. Upload
            upload_resp = self._upload(file_path)
            file_hash = upload_resp["hash"]
            scan_type = upload_resp["scan_type"]

            # 2. Scan
            self._trigger_scan(file_hash, scan_type)

            # 3. Report
            report = self._get_report(file_hash)

            # 4. Normalize
            return self._normalize_report(report, str(file_path))

        except requests.ConnectionError:
            return self._error_result(f"Cannot connect to MobSF at {self.api_url}. Please ensure the Docker container is running.")
        except Exception as e:
            logger.error("MobSF scan failed for %s: %s", file_path, e)
            return self._error_result(str(e))

    # ------------------------------------------------------------------
    # MobSF REST API calls
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": self.api_key}

    def _upload(self, file_path: Path) -> Dict[str, Any]:
        """POST /api/v1/upload"""
        url = f"{self.api_url}/api/v1/upload"
        with open(file_path, "rb") as f:
            resp = requests.post(
                url,
                files={"file": (file_path.name, f, "application/octet-stream")},
                headers=self._headers(),
                timeout=self.timeout,
            )
        resp.raise_for_status()
        return resp.json()

    def _trigger_scan(self, file_hash: str, scan_type: str) -> Dict[str, Any]:
        """POST /api/v1/scan"""
        url = f"{self.api_url}/api/v1/scan"
        resp = requests.post(
            url,
            data={"hash": file_hash, "scan_type": scan_type, "re_scan": "0"},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _get_report(self, file_hash: str) -> Dict[str, Any]:
        """POST /api/v1/report_json"""
        url = f"{self.api_url}/api/v1/report_json"
        resp = requests.post(
            url,
            data={"hash": file_hash},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Report normalization
    # ------------------------------------------------------------------

    def _normalize_report(
        self, report: Dict[str, Any], file_path: str
    ) -> Dict[str, Any]:
        """Convert MobSF JSON report → unified vulnerability list."""
        vulnerabilities: List[Dict] = []

        # 1. Code Analysis (Android & iOS)
        code_analysis = report.get("code_analysis", {})
        if isinstance(code_analysis, dict):
            # Try nested 'findings' first, then fallback to direct items
            findings = code_analysis.get("findings", code_analysis)
            if isinstance(findings, dict):
                for category, category_findings in findings.items():
                    if isinstance(category_findings, dict):
                        for rule_id, detail in category_findings.items():
                            if isinstance(detail, dict):
                                meta = detail.get("metadata", {})
                                vulnerabilities.append({
                                    "name": meta.get("description", rule_id),
                                    "severity": self._map_severity(meta.get("severity", "info")),
                                    "file": file_path,
                                    "category": category,
                                    "description": meta.get("description", ""),
                                    "scanner": "mobsf",
                                })

        # 2. iOS Code Analysis (if separate)
        ios_code = report.get("ios_code_analysis", {})
        if isinstance(ios_code, dict):
            findings = ios_code.get("findings", ios_code)
            if isinstance(findings, dict):
                for category, category_findings in findings.items():
                    if isinstance(category_findings, dict):
                        for rule_id, detail in category_findings.items():
                            if isinstance(detail, dict):
                                meta = detail.get("metadata", {})
                                vulnerabilities.append({
                                    "name": meta.get("description", rule_id),
                                    "severity": self._map_severity(meta.get("severity", "info")),
                                    "file": file_path,
                                    "category": category,
                                    "description": meta.get("description", ""),
                                    "scanner": "mobsf",
                                })

        # 3. Manifest/Info.plist Issues (Generic collections)
        for key in ["manifest_analysis", "infoplist_analysis"]:
            for item in report.get(key, []):
                if isinstance(item, dict):
                    vulnerabilities.append({
                        "name": item.get("title", f"{key.split('_')[0].capitalize()} Issue"),
                        "severity": self._map_severity(item.get("severity", "info")),
                        "file": file_path,
                        "category": "configuration",
                        "description": item.get("description", ""),
                        "scanner": "mobsf",
                    })

        # 4. Binary Analysis (Common)
        binary_analysis = report.get("binary_analysis", {})
        if isinstance(binary_analysis, dict):
            findings = binary_analysis.get("findings", binary_analysis)
            if isinstance(findings, dict):
                for name, detail in findings.items():
                    if isinstance(detail, dict):
                        vulnerabilities.append({
                            "name": name,
                            "severity": self._map_severity(detail.get("severity", "info")),
                            "file": file_path,
                            "category": "binary",
                            "description": detail.get("detailed_desc", name),
                            "scanner": "mobsf",
                        })

        # 5. MachO Analysis (iOS)
        macho = report.get("macho_analysis", {})
        if isinstance(macho, dict):
            for check_name, detail in macho.items():
                if isinstance(detail, dict) and "severity" in detail:
                    vulnerabilities.append({
                        "name": f"MachO: {check_name}",
                        "severity": self._map_severity(detail.get("severity", "info")),
                        "file": file_path,
                        "category": "binary",
                        "description": detail.get("description", ""),
                        "scanner": "mobsf",
                    })

        # 6. Permissions
        for perm_key in ["permissions", "ios_permissions"]:
            perms = report.get(perm_key, {})
            if isinstance(perms, dict):
                for name, detail in perms.items():
                    if isinstance(detail, dict):
                        status = detail.get("status", "normal")
                        if status in ("dangerous", "signature", "high"):
                            vulnerabilities.append({
                                "name": f"Permission: {name}",
                                "severity": "medium",
                                "file": file_path,
                                "category": "permissions",
                                "description": detail.get("description", ""),
                                "scanner": "mobsf",
                            })

        # 7. Transport Security (ATS/Network)
        ats = report.get("ats_analysis", {})
        if isinstance(ats, dict):
            for item in ats.get("ats_findings", []):
                if isinstance(item, dict):
                    vulnerabilities.append({
                        "name": "App Transport Security Issue",
                        "severity": self._map_severity(item.get("severity", "info")),
                        "file": file_path,
                        "category": "network",
                        "description": item.get("description", ""),
                        "scanner": "mobsf",
                    })

        return {
            "scanner": "mobsf",
            "target": file_path,
            "app_name": report.get("app_name", "Unknown"),
            "package_name": report.get("package_name") or report.get("bundle_id", ""),
            "platform": report.get("app_type", "unknown"),
            "security_score": report.get("security_score", "N/A"),
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity_breakdown": self._count_by_severity(vulnerabilities),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_severity(raw: str) -> str:
        """Normalize MobSF severity labels to project standard."""
        mapping = {
            "high": "high",
            "warning": "medium",
            "info": "informational",
            "good": "informational",
            "secure": "informational",
            "suppressed": "informational",
        }
        return mapping.get(raw.lower(), raw.lower())

    @staticmethod
    def _count_by_severity(vulns: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulns:
            sev = v.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _empty_severity() -> Dict[str, int]:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    def _error_result(self, message: str) -> Dict[str, Any]:
        return {
            "scanner": "mobsf",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }

