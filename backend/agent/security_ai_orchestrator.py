import logging
import os
from typing import Any, Dict, List

from backend.agent.security_agents.threat_model_agent import ThreatModelAgent
from backend.agent.security_agents.vulnerability_agent import VulnerabilityAgent
from backend.agent.security_agents.attack_graph_agent import AttackGraphAgent
from backend.agent.security_agents.remediation_agent import RemediationAgent

logger = logging.getLogger(__name__)

class SecurityAIOrchestrator:

    def __init__(self):
        self.threat_agent = ThreatModelAgent()
        self.vuln_agent = VulnerabilityAgent()
        self.attack_agent = AttackGraphAgent()
        self.remediation_agent = RemediationAgent()

    def analyze(self, scan_results: Dict[str, Any], repo_path: str = None) -> Dict[str, Any]:
        """
        Perform AI analysis on scan results.
        """
        analysis = {
            "threat_model": self.threat_agent.analyze(scan_results),
            "vulnerability_analysis": self.vuln_agent.analyze(scan_results),
            "attack_graph_analysis": self.attack_agent.analyze(scan_results),
            "remediation": self.remediation_agent.analyze(scan_results)
        }

        return analysis

    def _get_high_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter scan results for High/Critical findings across all scanners."""
        high_findings = []
        # Support both 'findings' key and direct dict
        results = scan_results.get("findings", scan_results)

        for scanner_name, data in results.items():
            if isinstance(data, dict) and "vulnerabilities" in data:
                for v in data["vulnerabilities"]:
                    sev = v.get("severity", "low").lower()
                    if sev in ("high", "critical"):
                        high_findings.append(v)
        
        return high_findings