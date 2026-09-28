import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Correlates security findings from multiple scanners.
    Groups issues by CWE, target location, and vulnerability type.
    """

    def __init__(self):
        self.findings_map: Dict[str, Dict[str, Any]] = {}

    def correlate(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Merge findings from multiple scanners into a unified list.
        """
        all_findings = []
        findings_by_scanner = scan_results.get("findings", {})

        for scanner_name, result in findings_by_scanner.items():
            if "error" in result:
                continue
            
            # Extract vulnerabilities (handling different formats)
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                correlated_key = self._generate_key(vuln)
                
                if correlated_key not in self.findings_map:
                    self.findings_map[correlated_key] = self._create_correlated_finding(vuln, scanner_name)
                else:
                    self._update_correlated_finding(correlated_key, vuln, scanner_name)

        return list(self.findings_map.values())

    def _generate_key(self, vuln: Dict[str, Any]) -> str:
        """
        Generates a unique key for correlation based on CWE and location.
        If CWE is available, it is the primary identifier.
        """
        # Normalization
        cwe_list = vuln.get("cwe", [])
        cwe = "CWE-UNKNOWN"
        if isinstance(cwe_list, str):
            cwe = cwe_list
        elif isinstance(cwe_list, list) and len(cwe_list) > 0:
            cwe = cwe_list[0]
            
        location = vuln.get("matched_at") or vuln.get("location") or "global"
        
        # If we have a CWE, we correlate by CWE + Location
        if cwe != "CWE-UNKNOWN":
            return f"{cwe}|{location}"
            
        # Fallback to Name + Location if no CWE is available
        name = vuln.get("name", "unknown").lower().replace(" ", "_")
        return f"{name}|{location}"

    def _create_correlated_finding(self, vuln: Dict[str, Any], scanner: str) -> Dict[str, Any]:
        """Creates a new correlated finding entry with intelligent field mapping."""
        name = vuln.get("name") or vuln.get("rule_id") or vuln.get("secret_type") or "Unknown Finding"
        description = vuln.get("description") or vuln.get("message") or "No description available."
        remediation = vuln.get("remediation") or vuln.get("fix") or vuln.get("recommendation")
        
        # Location normalization
        matched_at = vuln.get("matched_at") or vuln.get("location")
        if not matched_at and vuln.get("file"):
            matched_at = f"{vuln.get('file')}:{vuln.get('line', '?')}"
            
        return {
            "name": name,
            "severity": vuln.get("severity", "low").lower(),
            "description": description,
            "remediation": remediation,
            "cwe": vuln.get("cwe"),
            "matched_at": matched_at,
            "scanners": [scanner],
            "references": vuln.get("reference") or vuln.get("references") or [],
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "evidence_count": 1
        }

    def _update_correlated_finding(self, key: str, vuln: Dict[str, Any], scanner: str):
        """Updates an existing correlated finding with new scanner evidence."""
        finding = self.findings_map[key]
        
        if scanner not in finding["scanners"]:
            finding["scanners"].append(scanner)
            finding["evidence_count"] += 1
            
        # Update references
        new_refs = vuln.get("reference") or vuln.get("references") or []
        if isinstance(new_refs, list):
            for ref in new_refs:
                if ref not in finding["references"]:
                    finding["references"].append(ref)
        
        # Severity escalation (take the highest)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        current_sev = severity_order.get(finding["severity"], 0)
        new_sev = severity_order.get(vuln.get("severity", "low").lower(), 0)
        
        if new_sev > current_sev:
            finding["severity"] = vuln.get("severity", "low").lower()
