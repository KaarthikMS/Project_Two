"""
Integration test for all scanners using the ScannerManager.

This script runs scanners through the official orchestrator to verify 
that the platform works end-to-end with proper Docker volume mounting
and result correlation.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from backend.orchestrator import ScannerManager
from backend.reports.report_generator import ReportGenerator

def run_comprehensive_test(target_url: str, target_dir: str):
    print("\n" + "="*50)
    print("      COMPREHENSIVE SECURITY SCAN INTEGRATION TEST")
    print("="*50)

    # Initialize manager and generator
    manager = ScannerManager(output_dir="/tmp/scans_test")
    generator = ReportGenerator()
    
    # 1. Test Web Scanners (Dockerized)
    print("\n--- Phase 1: Web Security Scanners (DAST) ---")
    web_params = {
        "scanners": ["zap", "nuclei"],
        "target": target_url
    }
    web_results = manager.run(web_params)
    web_report = generator.generate(web_results)
    print(f"Web Scan Status: {web_report['summary']['overall_status']}")
    print(f"Total Findings: {web_report['summary']['total_vulnerabilities']}")

    # 2. Test Specialized Scanners (Mobile/Binary)
    print("\n--- Phase 2: Specialized Scanners (Mobile/Binary) ---")
    specialized_params = {
        "scanners": ["mobsf", "desktop"],
        "target": target_dir # Scans binary files in the project path
    }
    spec_results = manager.run(specialized_params)
    spec_report = generator.generate(spec_results)
    print(f"Specialized Status: {spec_report['summary']['overall_status']}")
    print(f"Total Findings: {spec_report['summary']['total_vulnerabilities']}")

    # 3. Test Network Scanner (Dockerized)
    print("\n--- Phase 3: Network Security Scanner (Nmap) ---")
    nmap_params = {
        "scanners": ["nmap"],
        "target": "localhost"
    }
    nmap_results = manager.run(nmap_params)
    nmap_report = generator.generate(nmap_results)
    print(f"Nmap Findings: {nmap_report['summary']['total_vulnerabilities']}")

    # 3. Test Static Scanners (Python-based)
    print("\n--- Phase 3: Static Analysis Scanners (SAST/SCA) ---")
    static_params = {
        "scanners": ["semgrep", "secrets", "dependency"],
        "target": target_dir
    }
    static_results = manager.run(static_params)
    static_report = generator.generate(static_results)
    print(f"Static Findings: {static_report['summary']['total_vulnerabilities']}")

    print("\n" + "="*50)
    print("      ALL SCANNERS EXECUTED VIA ORCHESTRATOR")
    print("="*50)
    print(f"Final Report Path: {os.path.abspath('/tmp/scans_test')}")

if __name__ == "__main__":
    # Test against Juice Shop (Web) and current backend (Static)
    target_web = "https://owasp.org/www-project-juice-shop/"
    target_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Project backend dir
    
    run_comprehensive_test(target_web, target_path)