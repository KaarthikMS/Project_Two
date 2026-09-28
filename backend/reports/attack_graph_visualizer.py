"""
Attack Graph Visualizer - Generates visual attack chain diagrams from correlated findings.

Uses Graphviz to render CWE-based attack paths showing how vulnerabilities
chain together across an application.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AttackGraphVisualizer:
    """
    Generates attack graph visualizations from correlated security findings.
    
    The graph connects vulnerabilities by CWE category, showing how
    an attacker might chain multiple findings to escalate impact.
    """

    # CWE-based attack chain definitions
    ATTACK_CHAINS = {
        "credential_compromise": {
            "label": "Credential Compromise Chain",
            "cwes": ["CWE-798", "CWE-259", "CWE-532", "CWE-312"],
            "color": "#e74c3c",
        },
        "injection_to_rce": {
            "label": "Injection → RCE Chain",
            "cwes": ["CWE-89", "CWE-79", "CWE-94", "CWE-78"],
            "color": "#e67e22",
        },
        "crypto_weakness": {
            "label": "Cryptographic Weakness Chain",
            "cwes": ["CWE-327", "CWE-328", "CWE-326"],
            "color": "#f39c12",
        },
        "access_control": {
            "label": "Access Control Chain",
            "cwes": ["CWE-250", "CWE-269", "CWE-862"],
            "color": "#9b59b6",
        },
        "binary_exploitation": {
            "label": "Binary Exploitation Chain",
            "cwes": ["CWE-121", "CWE-119", "CWE-416", "CWE-494"],
            "color": "#2c3e50",
        },
    }

    def generate_graph(
        self,
        correlated_findings: List[Dict[str, Any]],
        output_file: str = "attack_graph",
    ) -> str:
        """
        Generate an attack graph from correlated findings.

        Args:
            correlated_findings: List of correlated finding dicts from CorrelationEngine
            output_file: Output filename (without extension)

        Returns:
            Path to the generated PNG file, or a text-based fallback
        """
        try:
            from graphviz import Digraph
            return self._render_graphviz(correlated_findings, output_file)
        except ImportError:
            logger.info("Graphviz not available. Generating text-based attack graph.")
            return self._render_text(correlated_findings, output_file)

    def _render_graphviz(
        self,
        findings: List[Dict[str, Any]],
        output_file: str,
    ) -> str:
        """Render a visual attack graph using Graphviz."""
        from graphviz import Digraph

        dot = Digraph(
            comment="Security Attack Graph",
            format="png",
            graph_attr={
                "rankdir": "LR",
                "bgcolor": "#1a1a2e",
                "fontcolor": "white",
                "label": f"Attack Graph — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                "labelloc": "t",
                "fontsize": "18",
                "fontname": "Helvetica",
            },
            node_attr={
                "style": "filled",
                "fontname": "Helvetica",
                "fontsize": "11",
                "shape": "box",
                "margin": "0.2",
            },
            edge_attr={
                "color": "#7f8c8d",
                "fontcolor": "#bdc3c7",
                "fontname": "Helvetica",
                "fontsize": "9",
            },
        )

        severity_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#3498db",
            "informational": "#95a5a6",
        }

        # Add finding nodes
        finding_nodes = {}
        for i, finding in enumerate(findings):
            node_id = f"F{i}"
            severity = finding.get("severity", "low")
            name = finding.get("name", "Unknown")[:40]
            scanners = ", ".join(finding.get("scanners", []))
            cwe = self._extract_cwe_id(finding.get("cwe", ""))

            label = f"{name}\\n[{severity.upper()}]\\nCWE: {cwe}\\nFound by: {scanners}"

            dot.node(
                node_id,
                label=label,
                fillcolor=severity_colors.get(severity, "#95a5a6"),
                fontcolor="white" if severity in ("critical", "high") else "black",
            )
            finding_nodes[node_id] = finding

        # Detect and draw attack chains
        chains_found = self._detect_chains(findings)

        for chain_name, chain_findings in chains_found.items():
            chain_info = self.ATTACK_CHAINS[chain_name]

            # Add chain cluster
            with dot.subgraph(name=f"cluster_{chain_name}") as sub:
                sub.attr(
                    label=chain_info["label"],
                    color=chain_info["color"],
                    style="dashed",
                    fontcolor="white",
                )

                # Connect findings in the chain
                for j in range(len(chain_findings) - 1):
                    src_idx = findings.index(chain_findings[j])
                    dst_idx = findings.index(chain_findings[j + 1])
                    dot.edge(
                        f"F{src_idx}",
                        f"F{dst_idx}",
                        label="escalates to",
                        color=chain_info["color"],
                        penwidth="2",
                    )

        # Add "Attacker" entry point
        dot.node(
            "ATTACKER",
            label="🎯 Attacker\\nEntry Point",
            fillcolor="#c0392b",
            fontcolor="white",
            shape="oval",
        )

        # Connect attacker to highest-severity findings
        for i, finding in enumerate(findings):
            if finding.get("severity") in ("critical", "high"):
                dot.edge("ATTACKER", f"F{i}", label="targets", style="dashed")

        # Add "Impact" node
        dot.node(
            "IMPACT",
            label="💥 Potential Impact\\nData Breach / RCE",
            fillcolor="#8e44ad",
            fontcolor="white",
            shape="oval",
        )

        # Connect critical findings to impact
        for i, finding in enumerate(findings):
            if finding.get("severity") == "critical":
                dot.edge(f"F{i}", "IMPACT", label="leads to", color="#e74c3c", penwidth="2")

        try:
            rendered_path = dot.render(output_file, cleanup=True)
            logger.info("Attack graph saved to: %s", rendered_path)
            return rendered_path
        except Exception as e:
            logger.warning("Graphviz render failed: %s. Falling back to text.", e)
            return self._render_text(findings, output_file)

    def _render_text(
        self,
        findings: List[Dict[str, Any]],
        output_file: str,
    ) -> str:
        """Generate a text-based attack graph when Graphviz is not available."""
        lines = [
            "=" * 60,
            "    ATTACK GRAPH — Text Visualization",
            f"    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "=" * 60,
            "",
            "  [ATTACKER] ──→ Entry Points:",
            "",
        ]

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "informational": []}
        for finding in findings:
            sev = finding.get("severity", "low")
            if sev in by_severity:
                by_severity[sev].append(finding)

        for sev in ["critical", "high", "medium", "low"]:
            if by_severity[sev]:
                lines.append(f"  ┌─ {sev.upper()} ─────────────────────────")
                for f in by_severity[sev]:
                    name = f.get("name", "Unknown")[:45]
                    cwe = self._extract_cwe_id(f.get("cwe", ""))
                    scanners = ", ".join(f.get("scanners", []))
                    lines.append(f"  │  ● {name}")
                    lines.append(f"  │    CWE: {cwe} | Found by: {scanners}")
                lines.append(f"  └──────────────────────────────────────")
                lines.append("")

        # Attack chains
        chains = self._detect_chains(findings)
        if chains:
            lines.append("  DETECTED ATTACK CHAINS:")
            for chain_name, chain_findings in chains.items():
                chain_info = self.ATTACK_CHAINS[chain_name]
                lines.append(f"    ⚡ {chain_info['label']}")
                names = [f.get("name", "?")[:30] for f in chain_findings]
                lines.append(f"       {'  →  '.join(names)}")
            lines.append("")

        lines.append("  [IMPACT] ──→ Data Breach / RCE / Privilege Escalation")
        lines.append("=" * 60)

        text_content = "\n".join(lines)

        # Save to file
        text_path = f"{output_file}.txt"
        with open(text_path, "w") as f:
            f.write(text_content)

        return text_path

    def _detect_chains(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Detect attack chains by matching finding CWEs to known chain patterns."""
        chains_found = {}

        for chain_name, chain_def in self.ATTACK_CHAINS.items():
            matched = []
            for finding in findings:
                cwe_id = self._extract_cwe_id(finding.get("cwe", ""))
                if cwe_id in chain_def["cwes"]:
                    matched.append(finding)

            if len(matched) >= 2:
                chains_found[chain_name] = matched

        return chains_found

    @staticmethod
    def _extract_cwe_id(cwe_value: Any) -> str:
        """Extract a clean CWE ID from various formats."""
        if isinstance(cwe_value, list) and cwe_value:
            cwe_str = str(cwe_value[0])
        elif isinstance(cwe_value, str):
            cwe_str = cwe_value
        else:
            return "N/A"

        # Extract just the CWE-XXX part
        if "CWE-" in cwe_str:
            parts = cwe_str.split(":")
            return parts[0].strip()
        return cwe_str or "N/A"