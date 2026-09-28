#!/usr/bin/env python3
"""
POC Demo Runner — End-to-End Security Scan with Full Reporting.

This script is the single entry point for demonstrating the Project_Two
platform. It runs scanners, correlates findings, generates Markdown & JSON
reports, and produces an attack graph visualization.

Usage (Pre-AWS / Local):
  # Quick self-scan (no Docker needed)
  python3 run_poc_demo.py

  # Scan a specific directory
  python3 run_poc_demo.py --target /path/to/code

  # Choose specific scanners
  python3 run_poc_demo.py --scanners semgrep,secrets

  # Full suite including Docker scanners (requires Docker running)
  python3 run_poc_demo.py --scanners semgrep,secrets,dependency,mobsf,desktop

Usage (Post-AWS):
  # Trigger via Lambda / Bedrock Agent (scan_types param controls scanners)
  aws lambda invoke --function-name SecurityController --payload '{...}'
"""

import argparse
import json
import os
import sys
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.orchestrator import ScannerManager
from backend.reports.report_generator import ReportGenerator
from backend.reports.attack_graph_visualizer import AttackGraphVisualizer
from backend.agent.security_agents.vulnerability_agent import VulnerabilityAgent
from backend.agent.security_agents.remediation_agent import RemediationAgent
from backend.agent.security_agents.threat_model_agent import ThreatModelAgent
from backend.agent.security_agents.attack_graph_agent import AttackGraphAgent


import logging

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )
    # Silence third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(
        description="Project_Two — POC Security Scan Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_poc_demo.py                                    # Self-scan (default)
  python3 run_poc_demo.py --target ./my_app                  # Scan a directory
  python3 run_poc_demo.py --scanners semgrep,secrets         # Specific scanners
  python3 run_poc_demo.py --scanners mobsf --target app.apk  # Mobile scan
        """,
    )
    parser.add_argument(
        "--target",
        default=str(PROJECT_ROOT / "backend"),
        help="Path to scan (directory or file). Default: project's own backend/",
    )
    parser.add_argument(
        "--scanners",
        default="semgrep,secrets,dependency",
        help="Comma-separated scanner list. Default: semgrep,secrets,dependency",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "backend" / "reports" / "poc_demo"),
        help="Output directory for reports. Default: backend/reports/poc_demo/",
    )
    args = parser.parse_args()
    target = args.target
    # Only resolve to absolute path if it is NOT a URL and DOES exist as a local path
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output, f"run_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    scanners = [s.strip() for s in args.scanners.split(",")]
    
    # Revert hostname to https:// format if it's a network target without protocol
    network_scanners = {"nmap", "zap", "nuclei"}
    is_network_scanner_selected = any(s in network_scanners for s in scanners)
    
    if is_network_scanner_selected and not (target.startswith("http://") or target.startswith("https://")) and not os.path.exists(target):
        target = f"https://{target}"
        print(f"     ℹ️  Converting network target to: {target}")

    _print_banner()
    print(f"  📁 Target:   {target}")
    print(f"  🔍 Scanners: {', '.join(scanners)}")
    print(f"  📂 Output:   {output_dir}")
    print()

    # Validate target existence for local files
    is_url = target.startswith("http://") or target.startswith("https://")
    is_file = os.path.exists(target)
    
    # Network targets (hostnames/IPs) - allowed if network scanners are used
    is_network_target = not is_url and not is_file and is_network_scanner_selected

    if not is_url and not is_file and not is_network_target:
        print(f"  ❌ ERROR: Target path does not exist: {target}")
        print(f"     Please ensure you are providing a valid file path, a URL, or a network hostname.")
        sys.exit(1)

    # ── Step 1: Run Scanners ────────────────────────────────────────
    _print_step(1, "Running Security Scanners")
    manager = ScannerManager(output_dir=output_dir)
    scan_params = {"scanners": scanners, "target": target}
    
    results = {"findings": {}, "correlated_findings": [], "status": "in_progress"}
    try:
        results = manager.run(scan_params)
    except KeyboardInterrupt:
        # Note: ScannerManager.run now catches KeyboardInterrupt internally
        # but if it somehow bubbles up, we still want to proceed.
        print("\n  ⚠️  Scan interrupted by user. Proceeding with partial results...")
        if results.get("status") == "in_progress":
            results["status"] = "interrupted"
    except Exception as e:
        print(f"\n  ❌ ERROR during scan: {e}")
        results["status"] = "failed"

    scan_id = results.get("scan_id", "unknown")
    findings_dict = results.get("findings", {})
    if not isinstance(findings_dict, dict):
        findings_dict = {}
        
    raw_findings = sum(
        s.get("total", 0) for s in findings_dict.values() if isinstance(s, dict)
    )
    correlated = results.get("correlated_findings", [])
    if not isinstance(correlated, list):
        correlated = []

    print(f"  ✅ Scan complete (ID: {scan_id})")
    print(f"     Raw findings:       {raw_findings}")
    print(f"     Correlated issues:  {len(correlated)}")
    print()

    # ── Step 1.5: AI Assessment (Amazon Bedrock) ────────────────────
    ai_analysis = None
    analysis_result = {}
    try:
        # Check for AWS credentials
        boto3.client('sts', region_name='ap-south-1').get_caller_identity()
        
        _print_step(2, "AI Security Assessment (Amazon Bedrock)")
        print("  🤖 Connecting to Unified AI Orchestrator...")
        
        from backend.agent.security_ai_orchestrator import SecurityAIOrchestrator
        orchestrator = SecurityAIOrchestrator()

        # The orchestrator handles all agents (Threat, Vuln, Attack, Remediation)
        analysis_result = orchestrator.analyze(
            results, 
            repo_path=target if os.path.isdir(target) else str(Path(target).parent)
        )

        # Map back to old reporting format for compatibility
        triage_report = analysis_result["vulnerability_analysis"]
        rem_report = analysis_result["remediation"]
        threat_report = analysis_result["threat_model"]
        attack_report = analysis_result.get("attack_graph_analysis", "No attack graph generated.")
        
        ai_analysis = f"{triage_report}\n\n---\n\n{rem_report}\n\n---\n\n{threat_report}\n\n---\n\n{attack_report}"

        print("  ✅ AI Analysis complete.")
        print()
            
    except (NoCredentialsError, PartialCredentialsError):
        print("  ℹ️ Skipping Bedrock AI Assessment (No AWS credentials found in environment)")
        print()
    except Exception as e:
        print(f"  ⚠️ Skipping Bedrock AI Assessment (Error: {e})")
        print()

    # ── Step 2: Generate Reports ────────────────────────────────────
    _print_step(3, "Generating Reports")

    generator = ReportGenerator()

    # JSON report
    json_report = generator.generate(results, report_format="json", ai_analysis=ai_analysis)
    json_path = os.path.join(output_dir, "security_report.json")
    with open(json_path, "w") as f:
        f.write(json_report["content"])
    print(f"  📄 JSON report:    {json_path}")

    # Markdown report
    md_report = generator.generate(results, report_format="markdown", ai_analysis=ai_analysis)
    md_path = os.path.join(output_dir, "security_report.md")
    with open(md_path, "w") as f:
        f.write(md_report["content"])
    print(f"  📝 Markdown report: {md_path}")

    # HTML Interactive Dashboard
    html_report = generator.generate(results, report_format="html", ai_analysis=ai_analysis)
    html_path = os.path.join(output_dir, "security_report.html")
    with open(html_path, "w") as f:
        f.write(html_report["content"])
    print(f"  🎨 HTML Dashboard:  {html_path}")
    print()

    # ── Step 3: Attack Graph ────────────────────────────────────────
    _print_step(4, "Generating Attack Graph")

    visualizer = AttackGraphVisualizer()
    graph_output = os.path.join(output_dir, "attack_graph")
    graph_path = visualizer.generate_graph(correlated, output_file=graph_output)
    print(f"  🗺️  Attack graph:   {graph_path}")
    print()

    # ── Step 4: Terminal Summary ────────────────────────────────────
    _print_step(5, "Security Posture Summary")
    summary = md_report["summary"]

    print(f"  Status:         {summary['overall_status']}")
    if results.get("status") == "partial_failure":
         print(f"  ⚠️ Warning: Some scanners failed. See logs for details.")
    print(f"  Quality Gate:   {'✅ Passed' if summary['quality_gate_passed'] else '❌ Failed'}")
    print(f"  Scanners Used:  {', '.join(summary.get('scanners_used', []))}")
    print()
    print("  ┌──────────────────────────────────┐")
    print("  │  Severity    │  Count             │")
    print("  ├──────────────────────────────────┤")
    for sev, count in summary["severity_counts"].items():
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}.get(sev, "")
        print(f"  │  {icon} {sev.upper():<14}│  {count:<19}│")
    print("  └──────────────────────────────────┘")
    print()

    # Top correlated findings
    if correlated:
        print("  Top Correlated Findings:")
        for finding in correlated[:5]:
            sev = finding.get("severity", "low").upper()
            name = finding.get("name", "Unknown")[:50]
            scanners_str = ", ".join(finding.get("scanners", []))
            print(f"    [{sev}] {name}")
            print(f"           Found by: {scanners_str}")
        print()

    # Compliance summary
    compliance = summary.get("compliance", {})
    if compliance.get("owasp"):
        print("  OWASP Top 10 Hits:")
        for cat, count in compliance["owasp"].items():
            print(f"    • {cat}: {count}")
        print()

    _print_footer(output_dir)


def _print_banner():
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║  🛡️  Project_Two — AI Security Intelligence POC     ║")
    print("  ║  End-to-End Security Scan & Report Demo             ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()


def _print_step(n: int, title: str):
    print(f"  ── Step {n}: {title} {'─' * (40 - len(title))}")
    print()


def _print_footer(output_dir: str):
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║  ✅ POC Demo Complete!                              ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  📂 All artifacts saved to: {output_dir}")
    print()
    print("  Files generated:")
    for f in sorted(os.listdir(output_dir)):
        size = os.path.getsize(os.path.join(output_dir, f))
        print(f"    • {f} ({size:,} bytes)")
    print()


if __name__ == "__main__":
    main()
