"""
Dependency Scanner - Multi-ecosystem dependency vulnerability scanner.

Supports:
- Python (pip-audit)
- Node.js (npm audit)
- Universal fallback (OSV Scanner)

Automatically detects dependency files and runs the appropriate scanner.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


DEPENDENCY_FILES = {
    # Primary ecosystems with dedicated scanners (pip-audit, npm audit)
    "python": ["requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock"],
    "node": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    
    # Extended ecosystems supported via Universal Fallback (OSV-Scanner)
    "dart": ["pubspec.yaml", "pubspec.lock"],
    "go": ["go.mod", "go.sum"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "php": ["composer.json", "composer.lock"],
    "csharp": ["*.csproj", "packages.config"],
    "elixir": ["mix.exs", "mix.lock"],
    "swift": ["Package.swift", "Package.resolved"],
    "cpp": ["conanfile.txt", "vcpkg.json"],
}


class DependencyScanner:

    def scan(self, target_path: str) -> dict[str, Any]:

        repo = Path(target_path)

        vulnerabilities = []
        detected_files = []

        # detect dependency files
        for ecosystem, files in DEPENDENCY_FILES.items():
            for file in files:
                matches = list(repo.rglob(file))
                if matches:
                    detected_files.extend(matches)

                    if ecosystem == "python":
                        vulnerabilities.extend(self._scan_python(matches))

                    if ecosystem == "node":
                        vulnerabilities.extend(self._scan_node(matches))

        # fallback universal scanner
        vulnerabilities.extend(self._scan_osv(repo))

        unique = self._deduplicate(vulnerabilities)

        return {
            "scanner": "dependency",
            "target": target_path,
            "requirements_files": [str(f) for f in detected_files],
            "total": len(unique),
            "vulnerabilities": unique,
            "severity_breakdown": self._count_by_severity(unique),
        }

    def _map_severity(self, pkg: dict) -> str:
        sev = pkg.get("severity", "").lower()
        if sev in ["critical", "high", "medium", "low", "informational"]:
            return sev
        return "medium"

    def _scan_python(self, files: list[Path]) -> list[dict]:

        findings = []

        for req_file in files:

            try:
                result = subprocess.run(
                    ["pip-audit", "-r", str(req_file), "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if not result.stdout.strip():
                    return []

                data = json.loads(result.stdout)

                for vuln in data.get("dependencies", []):
                    for issue in vuln.get("vulns", []):

                        findings.append({
                            "package": vuln.get("name"),
                            "version": vuln.get("version"),
                            "severity": "high",
                            "vulnerability_id": issue.get("id"),
                            "description": issue.get("description", ""),
                            "scanner": "dependency",
                        })

            except Exception as e:
                logger.warning("pip-audit run failed: %s", str(e))

        return findings

    def _scan_node(self, files: list[Path]) -> list[dict]:

        findings = []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)

            advisories = data.get("vulnerabilities", {})

            for package, vuln in advisories.items():

                severity = vuln.get("severity", "medium")

                findings.append({
                    "package": package,
                    "severity": severity,
                    "description": vuln.get("title", ""),
                    "scanner": "dependency",
                })

        except Exception as e:
            logger.warning("npm audit failed: %s", str(e))

        return findings

    def _scan_osv(self, repo: Path) -> list[dict]:

        findings = []

        try:
            result = subprocess.run(
                ["osv-scanner", "--format", "json", str(repo)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)

            for res in data.get("results", []):
                for pkg in res.get("packages", []):
                    for vuln in pkg.get("vulnerabilities", []):

                        findings.append({
                            "package": pkg.get("package", {}).get("name"),
                            "severity": "high",
                            "vulnerability_id": vuln.get("id"),
                            "description": vuln.get("summary", ""),
                            "scanner": "dependency",
                        })

        except FileNotFoundError:
            logger.info("osv-scanner not installed, skipping.")

        except Exception as e:
            logger.warning("OSV scan failed: %s", str(e))

        return findings

    def _deduplicate(self, vulns: list[dict]) -> list[dict]:

        seen = set()
        unique = []

        for v in vulns:

            key = (
                v.get("package"),
                v.get("vulnerability_id"),
            )

            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique

    def _count_by_severity(self, vulnerabilities: list[dict]) -> dict[str, int]:

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()

            if sev in counts:
                counts[sev] += 1

        return counts