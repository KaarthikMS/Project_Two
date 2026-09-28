import json
import logging
import subprocess
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

# Default Semgrep rulesets for comprehensive coverage
DEFAULT_RULESETS = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/secrets",
    "p/ci",
]

# Comprehensive list of supported languages as requested
SUPPORTED_LANGUAGES = (
    "apex", "bash", "c", "c#", "c++", "cairo", "circom", "clojure", "cpp", "csharp",
    "dart", "docker", "dockerfile", "elixir", "ex", "fga", "generic", "go", "golang",
    "gosu", "hack", "hcl", "html", "java", "javascript", "js", "json", "jsonnet",
    "julia", "kotlin", "kt", "lisp", "lua", "move_on_aptos", "move_on_sui", "none",
    "ocaml", "openfga", "php", "promql", "proto", "proto3", "protobuf", "py",
    "python", "python2", "python3", "ql", "r", "regex", "ruby", "rust", "scala",
    "scheme", "sh", "sol", "solidity", "swift", "terraform", "tf", "ts", "typescript",
    "vue", "xml", "yaml"
)

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class SemgrepScanner:
    """
    Static analysis scanner using Semgrep with advanced SonarQube-like features.

    Features:
    - Leak Period Analysis: Detects new vs. legacy vulnerabilities.
    - Quality Gates: Customizable failure thresholds for new findings.
    - Compliance Mapping: OWASP Top 10, CWE, and SANS Top 25 support.

    Supported Languages:
    apex, bash, c, c#, c++, cairo, circom, clojure, cpp, csharp, dart, docker,
    dockerfile, elixir, ex, fga, generic, go, golang, gosu, hack, hcl, html,
    java, javascript, js, json, jsonnet, julia, kotlin, kt, lisp, lua,
    move_on_aptos, move_on_sui, none, ocaml, openfga, php, promql, proto,
    proto3, protobuf, py, python, python2, python3, ql, r, regex, ruby, rust,
    scala, scheme, sh, sol, solidity, swift, terraform, tf, ts, typescript,
    vue, xml, yaml
    """

    def __init__(
        self, 
        rulesets: List[str] | None = None, 
        timeout: int = 600,
        history_dir: str = "history/semgrep",
        quality_gate: Dict[str, int] | None = None
    ):
        self.rulesets = rulesets or DEFAULT_RULESETS
        self.timeout = timeout
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        # Default quality gate: fail if any new high severity vulnerabilities found
        self.quality_gate = quality_gate or {"high": 0}

    def scan(self, target_path: str) -> Dict[str, Any]:
        """
        Run Semgrep on the target directory or file with historical analysis.
        """
        path = Path(target_path).absolute()
        if not path.exists():
            return self._error_result(f"Target path does not exist: {target_path}")

        logger.info("Starting Semgrep scan on: %s", target_path)

        all_vulnerabilities = []
        errors = []

        try:
            # Intelligent Ruleset Selection
            detected_languages = self._detect_languages(target_path)
            dynamic_rulesets = list(self.rulesets)
            
            # Only these languages have verified p/{lang} community rulesets on semgrep.dev
            valid_ruleset_langs = {"python", "javascript", "typescript", "java", "golang", "ruby", "csharp", "php"}
            
            for lang in detected_languages:
                if lang in valid_ruleset_langs:
                    # Add language-specific community rulesets
                    lang_ruleset = f"p/{lang}"
                    if lang_ruleset not in dynamic_rulesets:
                        dynamic_rulesets.append(lang_ruleset)
            
            logger.info("Detected languages: %s. Using rulesets: %s", detected_languages, dynamic_rulesets)

            # Optimize: Run all rulesets in a single Semgrep execution
            all_vulnerabilities = self._run_semgrep_unified(str(path), dynamic_rulesets)
        except Exception as e:
            logger.error("Semgrep unified scan failed: %s", str(e))
            errors.append({"error": str(e)})

        # Deduplicate results
        seen = set()
        unique_vulnerabilities = []
        for vuln in all_vulnerabilities:
            key = (vuln.get("rule_id"), vuln.get("file"), vuln.get("line"), vuln.get("message"))
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)

        # Historical Analysis (Leak Period)
        target_id = hashlib.md5(str(path).encode()).hexdigest()
        history_file = self.history_dir / f"{target_id}.json"
        
        # Identify New Vulnerabilities (Leak Period)
        # Note: History logic remains similar but uses the deduplicated list
        self._apply_leak_period_logic(unique_vulnerabilities, history_file)

        # Quality Gate Evaluation
        quality_gate_passed = True
        gate_failures = []
        new_counts = self._count_by_severity([v for v in unique_vulnerabilities if v.get("is_new")])
        
        for sev, limit in self.quality_gate.items():
            if new_counts.get(sev, 0) > limit:
                quality_gate_passed = False
                gate_failures.append(f"Quality Gate failed: {new_counts[sev]} new {sev} vulnerabilities (limit: {limit})")

        # Save History
        timestamp = datetime.now(timezone.utc).isoformat()
        current_scan_data = {
            "timestamp": timestamp,
            "target": str(path),
            "total": len(unique_vulnerabilities),
            "vulnerabilities": unique_vulnerabilities
        }
        try:
            with open(history_file, 'w') as f:
                json.dump(current_scan_data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save history: %s", e)

        return {
            "scanner": "semgrep",
            "target": str(path),
            "timestamp": timestamp,
            "total": len(unique_vulnerabilities),
            "new_vulnerabilities": len([v for v in unique_vulnerabilities if v.get("is_new")]),
            "quality_gate": {
                "passed": quality_gate_passed,
                "failures": gate_failures
            },
            "compliance": self._get_compliance_summary(unique_vulnerabilities),
            "vulnerabilities": unique_vulnerabilities,
            "severity_breakdown": self._count_by_severity(unique_vulnerabilities),
            "errors": errors,
        }

    def _run_semgrep_unified(self, target_path: str, rulesets: List[str]) -> List[Dict]:
        """Execute Semgrep with multiple rulesets in one go."""
        cmd = ["semgrep", "--json", "--timeout", str(self.timeout), "--no-git-ignore"]
        for rs in rulesets:
            cmd.extend(["--config", rs])
        cmd.append(target_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60,
            )
        except FileNotFoundError:
            # Fallback to absolute path in .venv if not in global PATH
            venv_semgrep = Path(".venv/bin/semgrep")
            if venv_semgrep.exists():
                cmd[0] = str(venv_semgrep)
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 60)
                except Exception:
                    return []
            else:
                return []
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out on %s", target_path)
            return []

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Semgrep output. stderr: %s", result.stderr)
            return []

        vulnerabilities = []
        for result_item in output.get("results", []):
            extra = result_item.get("extra", {})
            metadata = extra.get("metadata", {})
            severity = SEVERITY_MAP.get(extra.get("severity", "WARNING"), "medium")

            owasp_refs = metadata.get("owasp", [])
            if isinstance(owasp_refs, str):
                owasp_refs = [owasp_refs]

            vulnerabilities.append({
                "rule_id": result_item.get("check_id", "unknown"),
                "severity": severity,
                "file": result_item.get("path", ""),
                "line": result_item.get("start", {}).get("line", 0),
                "end_line": result_item.get("end", {}).get("line", 0),
                "message": extra.get("message", ""),
                "code_snippet": extra.get("lines", ""),
                "cwe": metadata.get("cwe", []),
                "owasp": owasp_refs,
                "references": metadata.get("references", []),
                "fix": extra.get("fix", None),
                "scanner": "semgrep",
            })

        return vulnerabilities

    def _apply_leak_period_logic(self, vulns: List[Dict], history_file: Path):
        """Internal helper to identify new vs legacy findings."""
        previous_findings: List[Dict] = []
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    history_data = json.load(f)
                    previous_findings = history_data.get("vulnerabilities", [])
            except Exception as e:
                logger.error("Failed to load history: %s", e)

        previous_keys = { (v.get("rule_id"), v.get("file"), v.get("message")) for v in previous_findings }
        
        for vuln in vulns:
            current_key = (vuln.get("rule_id"), vuln.get("file"), vuln.get("message"))
            vuln["is_new"] = current_key not in previous_keys
            if not vuln["is_new"]:
                 for prev in previous_findings:
                     if (prev.get("rule_id"), prev.get("file"), prev.get("message")) == current_key:
                         vuln["discovered_at"] = prev.get("discovered_at") or prev.get("timestamp")
                         break
            else:
                vuln["discovered_at"] = datetime.now(timezone.utc).isoformat()

    def _get_compliance_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Group vulnerabilities by compliance standards (OWASP, CWE, SANS)."""
        summary: Dict[str, Dict[str, int]] = {
            "owasp": {},
            "cwe": {},
            "sans": {}
        }
        
        sans_map = {
            # SANS Top 25 (2023 list mapping approximation)
            "CWE-787": "SANS-Top-25", # Out-of-bounds Write
            "CWE-79": "SANS-Top-25",  # XSS
            "CWE-89": "SANS-Top-25",  # SQL Injection
            "CWE-20": "SANS-Top-25",  # Improper Input Validation
            "CWE-125": "SANS-Top-25", # Out-of-bounds Read
            "CWE-78": "SANS-Top-25",  # OS Command Injection
            "CWE-416": "SANS-Top-25", # Use After Free
            "CWE-22": "SANS-Top-25",  # Path Traversal
            "CWE-352": "SANS-Top-25", # CSRF
            "CWE-434": "SANS-Top-25", # Unrestricted Upload of File with Dangerous Type
            "CWE-862": "SANS-Top-25", # Missing Authorization
            "CWE-476": "SANS-Top-25", # NULL Pointer Dereference
            "CWE-287": "SANS-Top-25", # Improper Authentication
            "CWE-190": "SANS-Top-25", # Integer Overflow or Wraparound
            "CWE-502": "SANS-Top-25", # Deserialization of Untrusted Data
            "CWE-798": "SANS-Top-25", # Hardcoded Credentials
            "CWE-77": "SANS-Top-25",  # Command Injection
            "CWE-306": "SANS-Top-25", # Missing Authentication for Critical Function
            "CWE-119": "SANS-Top-25", # Memory Corruption
            "CWE-276": "SANS-Top-25", # Incorrect Default Permissions
        }

        for v in vulnerabilities:
            for category in v.get("owasp", []):
                summary["owasp"][category] = summary["owasp"].get(category, 0) + 1
            for cwe_list in v.get("cwe", []):
                cwe = str(cwe_list)
                summary["cwe"][cwe] = summary["cwe"].get(cwe, 0) + 1
                cwe_id = cwe.split(":")[0].strip()
                if cwe_id in sans_map:
                    sans_cat = sans_map[cwe_id]
                    summary["sans"][sans_cat] = summary["sans"].get(sans_cat, 0) + 1
        return summary


    def _count_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulnerabilities:
            sev = str(v.get("severity", "low")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts


    def _error_result(self, message: str) -> Dict[str, Any]:
        return {
            "scanner": "semgrep",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }

    def _detect_languages(self, target_path: str) -> Set[str]:
        """
        Scans the target directory and identifies languages based on file extensions.
        Maps common extensions to Semgrep language names.
        """
        detected = set()
        path = Path(target_path)
        
        if not path.exists():
            return detected

        ext_to_lang = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "golang",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".tf": "terraform",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".html": "html",
            ".sh": "bash",
            ".bash": "bash"
        }

        # If it's a single file
        if path.is_file():
            lang = ext_to_lang.get(path.suffix.lower())
            if lang:
                detected.add(lang)
            return detected

        # If it's a directory
        try:
            for filepath in path.rglob("*"):
                if filepath.is_file():
                    lang = ext_to_lang.get(filepath.suffix.lower())
                    if lang:
                        detected.add(lang)
        except Exception as e:
            logger.warning("Error detecting languages in %s: %s", target_path, e)
            
        return detected
