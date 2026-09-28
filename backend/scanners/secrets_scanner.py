"""
Secrets Scanner - Detects hardcoded secrets, API keys, and credentials in source code.

Uses multiple detection strategies:
- Pattern-based matching (regex for known secret formats)
- Entropy-based detection (high-entropy strings likely to be secrets)
- detect-secrets library integration
"""

import json
import logging
import math
import os
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Regex patterns for common secret types
SECRET_PATTERNS: dict[str, dict] = {
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID",
        "cwe": "CWE-798",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "description": "AWS Secret Access Key",
        "cwe": "CWE-798",
    },
    "github_token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        "severity": "critical",
        "description": "GitHub Personal Access Token",
        "cwe": "CWE-798",
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google API Key",
        "cwe": "CWE-798",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9A-Za-z]{10,48}",
        "severity": "high",
        "description": "Slack Token",
        "cwe": "CWE-798",
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Key / Certificate",
        "cwe": "CWE-321",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "severity": "medium",
        "description": "JSON Web Token (JWT)",
        "cwe": "CWE-522",
    },
    "db_connection_string": {
        "pattern": r"(?i)(postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@",
        "severity": "critical",
        "description": "Database Connection String with Credentials",
        "cwe": "CWE-798",
    },
    "generic_password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "severity": "high",
        "description": "Hardcoded Password",
        "cwe": "CWE-259",
    },
    "generic_api_key": {
        "pattern": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": "high",
        "description": "Hardcoded API Key",
        "cwe": "CWE-798",
    },
    "stripe_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "description": "Stripe Secret/Public Key",
        "cwe": "CWE-798",
    },
    "sendgrid_key": {
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "severity": "high",
        "description": "SendGrid API Key",
        "cwe": "CWE-798",
    },
}

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pyc", ".pyo", ".class", ".so", ".dll", ".exe",
    ".woff", ".woff2", ".ttf", ".eot",
}

# Directories to skip
SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".venv", "venv",
    "dist", "build", ".idea", ".vscode",
}

ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 20

# Known integrity hash prefixes (NPM, etc.)
KNOWN_HASH_PREFIXES = (
    "sha1-",
    "sha256-",
    "sha384-",
    "sha512-",
)

# Dependency files that cause false positives
FALSE_POSITIVE_FILES = {
    "package-lock.json",
    "package-lock.json.bak",
    "yarn.lock",
    "pnpm-lock.yaml",
}


class SecretsScanner:

    def __init__(self, use_detect_secrets: bool = True):
        self.use_detect_secrets = use_detect_secrets

    def scan(self, target_path: str) -> dict[str, Any]:

        path = Path(target_path)
        if not path.exists():
            return self._error_result(f"Path does not exist: {target_path}")

        logger.info("Starting secrets scan on: %s", target_path)

        vulnerabilities = []

        regex_findings = self._scan_with_regex(path)
        vulnerabilities.extend(regex_findings)

        if self.use_detect_secrets:
            ds_findings = self._scan_with_detect_secrets(str(path))
            vulnerabilities.extend(ds_findings)

        entropy_findings = self._scan_high_entropy(path)
        vulnerabilities.extend(entropy_findings)

        seen = set()
        unique = []

        for v in vulnerabilities:
            key = (v.get("file"), v.get("line"), v.get("secret_type"))
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return {
            "scanner": "secrets",
            "target": target_path,
            "total": len(unique),
            "vulnerabilities": unique,
            "severity_breakdown": self._count_by_severity(unique),
        }

    def _scan_with_regex(self, base_path: Path) -> list[dict]:

        findings = []
        files = self._get_scannable_files(base_path)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for line_num, line in enumerate(lines, start=1):
                    for secret_type, config in SECRET_PATTERNS.items():
                        matches = re.findall(config["pattern"], line)

                        for match in matches:
                            findings.append({
                                "secret_type": secret_type,
                                "severity": config["severity"],
                                "file": str(file_path),
                                "line": line_num,
                                "description": config["description"],
                                "cwe": config["cwe"],
                                "redacted_value": self._redact(match),
                                "code_snippet": line.strip()[:200],
                                "detection_method": "regex",
                                "scanner": "secrets",
                            })

            except (OSError, PermissionError):
                pass

        return findings

    def _scan_with_detect_secrets(self, target_path: str) -> list[dict]:

        try:
            result = subprocess.run(
                ["detect-secrets", "scan", "--all-files", target_path],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                return []

            output = json.loads(result.stdout)
            findings = []

            for file_path, secrets in output.get("results", {}).items():
                for secret in secrets:
                    findings.append({
                        "secret_type": secret.get("type", "unknown"),
                        "severity": "high",
                        "file": file_path,
                        "line": secret.get("line_number", 0),
                        "description": f"Potential secret detected: {secret.get('type')}",
                        "cwe": "CWE-798",
                        "redacted_value": "[REDACTED]",
                        "code_snippet": "",
                        "detection_method": "detect-secrets",
                        "hashed_secret": secret.get("hashed_secret", ""),
                        "scanner": "secrets",
                    })

            return findings

        except Exception:
            return []

    def _scan_high_entropy(self, base_path: Path) -> list[dict]:

        findings = []
        files = self._get_scannable_files(base_path)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for line_num, line in enumerate(lines, start=1):

                    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', line)

                    for candidate in candidates:

                        if candidate.startswith(KNOWN_HASH_PREFIXES):
                            continue

                        if len(candidate) > 120:
                            continue

                        entropy = self._shannon_entropy(candidate)

                        if entropy >= ENTROPY_THRESHOLD:
                            findings.append({
                                "secret_type": "high_entropy_string",
                                "severity": "medium",
                                "file": str(file_path),
                                "line": line_num,
                                "description": "High-entropy string that may be a secret or key",
                                "cwe": "CWE-798",
                                "redacted_value": self._redact(candidate),
                                "code_snippet": line.strip()[:200],
                                "entropy": round(entropy, 2),
                                "detection_method": "entropy",
                                "scanner": "secrets",
                            })

            except (OSError, PermissionError):
                pass

        return findings

    def _shannon_entropy(self, data: str) -> float:

        entropy = 0.0

        for char in set(data):
            p = data.count(char) / len(data)
            entropy -= p * math.log2(p)

        return entropy

    def _redact(self, secret: str) -> str:

        if len(secret) <= 6:
            return "***"

        return f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"

    def _get_scannable_files(self, base_path: Path) -> list[Path]:

        if base_path.is_file():
            return [base_path]

        files = []

        for root, dirs, filenames in os.walk(base_path):

            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for filename in filenames:

                if filename in FALSE_POSITIVE_FILES:
                    continue

                file_path = Path(root) / filename

                if file_path.suffix.lower() not in SKIP_EXTENSIONS:
                    files.append(file_path)

        return files

    def _count_by_severity(self, vulnerabilities: list[dict]) -> dict[str, int]:

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()

            if sev in counts:
                counts[sev] += 1

        return counts

    def _error_result(self, message: str) -> dict:

        return {
            "scanner": "secrets",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }