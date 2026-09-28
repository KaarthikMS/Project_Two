"""
Report Generator - Aggregates scan results into human-readable formats.

Supports Markdown, HTML, and JSON report generation with vulnerability
correlation, compliance mapping, and remediation summaries.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from backend.reports.html_report_generator import HtmlReportGenerator

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Consolidates findings from multiple scanners, deduplicates,
    calculates risk scores, and provides structured remediation guidance.
    """

    def __init__(self):
        self.html_generator = HtmlReportGenerator()

    def generate(
        self,
        scan_results: list[dict] | dict,
        report_format: str = "markdown",
        include_remediation: bool = True,
        ai_analysis: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a report from scan results.

        Args:
            scan_results: Orchestrator result dict OR list of result dicts from handler
            report_format: Output format ('markdown', 'json')
            include_remediation: Whether to include fix guidance
            ai_analysis: Optional Bedrock AI analysis text to include

        Returns:
            Dict containing the report content and metadata
        """
        # Normalize input: handle both orchestrator dict and handler list
        if isinstance(scan_results, dict):
            results_list = [scan_results]
        else:
            results_list = scan_results

        logger.info("Generating %s report for %d result sets", report_format, len(results_list))

        summary = self._generate_summary(results_list)

        if report_format == "json":
            report_data = {
                "summary": summary,
                "scans": results_list,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            if ai_analysis:
                report_data["ai_analysis"] = ai_analysis
            report_content = json.dumps(report_data, indent=2, default=str)
        elif report_format == "markdown":
            report_content = self._generate_markdown(summary, results_list, include_remediation, ai_analysis)
        elif report_format == "html":
            report_content = self.html_generator.generate(summary, results_list, ai_analysis)
        else:
            report_content = f"Format {report_format} not implemented yet."

        return {
            "format": report_format,
            "content": report_content,
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _generate_summary(self, results_list: list[dict]) -> dict:
        """Calculate overall vulnerability counts and risk level."""
        total_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        new_vulnerabilities = 0
        quality_gate_passed = True
        gate_failures = []
        scanners_used = []
        compliance = {"owasp": {}, "cwe": {}}

        for result in results_list:
            # Handle orchestrator output format
            findings_dict = result.get("findings", {})
            for scanner_name, scanner_result in findings_dict.items():
                if isinstance(scanner_result, dict) and "error" not in scanner_result:
                    scanners_used.append(scanner_name)
                    
                    # Severity counts
                    breakdown = scanner_result.get("severity_breakdown", {})
                    for severity, count in breakdown.items():
                        if severity in total_counts:
                            total_counts[severity] += count
                    
                    # New vulns
                    new_vulnerabilities += scanner_result.get("new_vulnerabilities", 0)

                    # Quality gate
                    gate = scanner_result.get("quality_gate", {})
                    if gate and not gate.get("passed", True):
                        quality_gate_passed = False
                        gate_failures.extend(gate.get("failures", []))

                    # Compliance aggregation
                    comp = scanner_result.get("compliance", {})
                    for owasp_key, count in comp.get("owasp", {}).items():
                        compliance["owasp"][owasp_key] = compliance["owasp"].get(owasp_key, 0) + count
                    for cwe_key, count in comp.get("cwe", {}).items():
                        compliance["cwe"][cwe_key] = compliance["cwe"].get(cwe_key, 0) + count

            # Also handle direct severity_breakdown (from handler format)
            direct_breakdown = result.get("severity_breakdown") or result.get("total_findings")
            if direct_breakdown and not findings_dict:
                for severity, count in direct_breakdown.items():
                    if severity in total_counts:
                        total_counts[severity] += count

        # Determine overall status
        status = "✅ SECURE"
        if not quality_gate_passed:
            status = "🚨 FAILED QUALITY GATE"
        elif total_counts["critical"] > 0:
            status = "🔴 CRITICAL RISK"
        elif total_counts["high"] > 0:
            status = "🟠 AT RISK"
        elif total_counts["medium"] > 0:
            status = "🟡 NEEDS ATTENTION"

        return {
            "overall_status": status,
            "total_vulnerabilities": sum(total_counts.values()),
            "new_vulnerabilities": new_vulnerabilities,
            "quality_gate_passed": quality_gate_passed,
            "gate_failures": gate_failures,
            "severity_counts": total_counts,
            "scanners_used": list(set(scanners_used)),
            "compliance": compliance,
        }

    def _generate_markdown(self, summary: dict, results_list: list[dict], include_remediation: bool, ai_analysis: str | None = None) -> str:
        """Create a comprehensive Markdown security report."""
        lines = [
            "# 🛡️ Project_Two — Security Assessment Report",
            f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"| Metric | Value |",
            f"| :--- | :--- |",
            f"| **Overall Status** | {summary['overall_status']} |",
            f"| **Total Findings** | {summary['total_vulnerabilities']} |",
            f"| **New Findings** | {summary['new_vulnerabilities']} |",
            f"| **Quality Gate** | {'✅ Passed' if summary['quality_gate_passed'] else '❌ Failed'} |",
            f"| **Scanners Used** | {', '.join(summary.get('scanners_used', []))} |",
            "",
        ]

        if ai_analysis:
            lines.append("## 🤖 AI Security Assessment (Amazon Bedrock)")
            lines.append("> *Analysis provided by Claude 3.5 Sonnet & Haiku with RAG Knowledge Base context.*")
            lines.append("")
            lines.append(ai_analysis)
            lines.append("")
            lines.append("---")
            lines.append("")

        # Quality gate failures
        if summary["gate_failures"]:
            lines.append("### ⚠️ Quality Gate Failures")
            for failure in summary["gate_failures"]:
                lines.append(f"- {failure}")
            lines.append("")

        # Severity breakdown
        lines.append("### Severity Breakdown")
        lines.append("| Severity | Count |")
        lines.append("| :--- | :---: |")
        for sev, count in summary["severity_counts"].items():
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}.get(sev, "")
            lines.append(f"| {icon} {sev.upper()} | {count} |")
        lines.append("")

        # Compliance mapping
        compliance = summary.get("compliance", {})
        if compliance.get("owasp"):
            lines.append("### OWASP Top 10 Mapping")
            lines.append("| OWASP Category | Findings |")
            lines.append("| :--- | :---: |")
            for category, count in sorted(compliance["owasp"].items()):
                lines.append(f"| {category} | {count} |")
            lines.append("")

        if compliance.get("cwe"):
            lines.append("### CWE Coverage")
            lines.append("| CWE | Findings |")
            lines.append("| :--- | :---: |")
            for cwe, count in sorted(compliance["cwe"].items()):
                lines.append(f"| {cwe} | {count} |")
            lines.append("")

        # Correlated findings
        lines.append("---")
        lines.append("")
        lines.append("## 🔗 Correlated Findings")
        lines.append("")

        for result in results_list:
            correlated = result.get("correlated_findings", [])
            if correlated:
                lines.append(f"*{len(correlated)} unique issues identified after cross-scanner correlation:*")
                lines.append("")
                for i, finding in enumerate(correlated, 1):
                    sev = finding.get("severity", "low").upper()
                    name = finding.get("name", "Unknown Finding")
                    scanners = ", ".join(finding.get("scanners", []))
                    evidence = finding.get("evidence_count", 1)

                    lines.append(f"### {i}. [{sev}] {name}")
                    lines.append(f"- **Detected by**: {scanners} ({evidence} evidence point{'s' if evidence > 1 else ''})")

                    desc = finding.get("description")
                    if desc:
                        lines.append(f"- **Description**: {desc}")

                    location = finding.get("matched_at")
                    if location:
                        lines.append(f"- **Location**: `{location}`")

                    cwe = finding.get("cwe")
                    if cwe:
                        lines.append(f"- **CWE**: {cwe}")

                    if include_remediation:
                        rem = finding.get("remediation") or "Consult CWE database for remediation guidance."
                        lines.append(f"- **Remediation**: {rem}")

                    refs = finding.get("references", [])
                    if refs:
                        lines.append(f"- **References**: {', '.join(refs[:3])}")

                    lines.append("")

        # Detailed scanner output
        lines.append("---")
        lines.append("")
        lines.append("## 📝 Detailed Scanner Output")
        lines.append("")

        for result in results_list:
            findings_dict = result.get("findings", {})
            for scanner_name, scanner_result in findings_dict.items():
                if isinstance(scanner_result, dict) and "error" not in scanner_result:
                    vulns = scanner_result.get("vulnerabilities", [])
                    if not vulns:
                        continue

                    lines.append(f"### Scanner: {scanner_name.upper()} ({len(vulns)} findings)")
                    lines.append("")

                    for vuln in vulns:
                        sev = vuln.get("severity", "low").upper()
                        name = vuln.get("name") or vuln.get("rule_id") or vuln.get("secret_type") or vuln.get("description", "Unknown")[:50]

                        lines.append(f"#### [{sev}] {name}")
                        lines.append(f"- **Description**: {vuln.get('description') or vuln.get('message', 'N/A')}")

                        if "file" in vuln:
                            lines.append(f"- **Location**: `{vuln['file']}` (Line {vuln.get('line', '?')})")
                        elif "url" in vuln:
                            lines.append(f"- **URL**: {vuln['url']}")

                        if "cwe" in vuln:
                            lines.append(f"- **CWE**: {vuln['cwe']}")

                        if include_remediation:
                            rem = vuln.get("remediation") or vuln.get("solution") or vuln.get("fix") or vuln.get("recommendation") or "Review and remediate."
                            lines.append(f"- **Remediation**: {rem}")

                        lines.append("")

        lines.append("---")
        lines.append(f"*Report generated by Project_Two AI Security Intelligence Platform*")

        return "\n".join(lines)
