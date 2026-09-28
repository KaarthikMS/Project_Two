import json
import logging
import subprocess
import os
import shutil
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.utils.correlation_engine import CorrelationEngine

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class ScannerManager:
    """
    Lightweight Orchestrator for Containerized Security Scanners.
    """
    
    # Capability Manifest tracking scanner requirements
    CAPABILITY_MANIFEST: Dict[str, Dict[str, Any]] = {
        # Docker-based Heavy Scanners
        "zap": {
            "type": "docker",
            "image": "ghcr.io/zaproxy/zaproxy:stable",
            "container_name": "dev_zap_scanner",
            "description": "OWASP ZAP DAST Scanner",
            "command_template": "zap-baseline.py -t {target} -J {report_name} -z \"-dir /tmp/zap_{report_name}\"",
            "run_prefix": "docker run --rm -v {output_dir}:/zap/wrk/:rw {image}",
            "exec_prefix": "docker exec {container_name}"
        },
        "nuclei": {
            "type": "docker",
            "image": "projectdiscovery/nuclei:latest",
            "container_name": "dev_nuclei_scanner",
            "description": "Nuclei Vulnerability Scanner",
            "command_template": "nuclei -u {target} -json-export /app/output/{report_name} -severity low,medium,high,critical -as -retries 2 -stats -si 30 -timeout 6",
            "run_prefix": "docker run --rm -v {output_dir}:/app/output -v {templates_dir}:/root/nuclei-templates:rw {image}",
            "exec_prefix": "docker exec {container_name}"
        },
        "nmap": {
            "type": "docker",
            "image": "instrumentisto/nmap",
            "container_name": "dev_nmap_scanner",
            "description": "Nmap Network Scanner",
            "requires_privileged": True,
            "command_template": "nmap -T4 -F -Pn -oX /tmp/nmap/{report_name} {target}",
            "run_prefix": "docker run --rm --privileged -v {output_dir}:/tmp/nmap {image}",
            "exec_prefix": "docker exec {container_name}"
        },
        
        # Local Python-based Scanners (Lightweight)
        "semgrep": {"type": "python", "class": "SemgrepScanner", "module": "backend.scanners.semgrep_scanner"},
        "secrets": {"type": "python", "class": "SecretsScanner", "module": "backend.scanners.secrets_scanner"},
        "dependency": {"type": "python", "class": "DependencyScanner", "module": "backend.scanners.dependency_scanner"},
        "mobsf": {"type": "python", "class": "MobSFScanner", "module": "backend.scanners.mobsf_scanner"},
        "desktop": {"type": "python", "class": "DesktopBinaryScanner", "module": "backend.scanners.desktop_scanner"},
        "binary": {"type": "python", "class": "DesktopBinaryScanner", "module": "backend.scanners.desktop_scanner"},
    }


    def __init__(self, output_dir: str = "/tmp/scans"):
        """Initialize the ScannerManager."""
        self.output_dir = output_dir
        self._import_lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)

    def is_scanner_available(self, scanner_name: str) -> bool:
        """
        Check to verify if the container runtime, binary, or python module is present.
        """
        if scanner_name not in self.CAPABILITY_MANIFEST:
            logger.warning(f"Scanner {scanner_name} not found in manifest.")
            return False

        capabilities = self.CAPABILITY_MANIFEST[scanner_name]
        stype = capabilities.get("type")
        
        if stype == "docker":
            if not shutil.which("docker"):
                logger.error("Docker is not installed or not in PATH.")
                return False
            
            image = str(capabilities.get("image", ""))
            try:
                result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
                return result.returncode == 0
            except Exception:
                return False
                
        elif stype == "python":
            try:
                import importlib
                importlib.import_module(capabilities["module"])
                return True
            except ImportError:
                return False

        return False

    def _sanitize_target(self, target: str, scanner_name: str) -> str:
        """Sanitize target string based on scanner requirements."""
        from urllib.parse import urlparse
        
        if scanner_name == "nmap":
            # Nmap wants Hostname or IP, not URL or local path
            if target.startswith("http"):
                 parsed = urlparse(target)
                 return parsed.hostname or target
            # If it looks like an absolute path but we are in Nmap, try to take the last part
            if target.startswith("/") and not os.path.exists(target):
                 return target.split("/")[-1]
            return target
        
        return target

    def _is_container_running(self, container_name: str) -> bool:
        """Check if a container is currently running."""
        try:
            # First check for specifically RUNNING
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={container_name}", "--filter", "status=running", "--format", "{{.Names}}"],
                capture_output=True, text=True, check=False
            )
            if container_name in result.stdout:
                return True
            
            # Check if it exists but is PAUSED (common cause of 'spawning' fallback)
            paused_check = subprocess.run(
                ["docker", "ps", "--filter", f"name={container_name}", "--filter", "status=paused", "--format", "{{.Names}}"],
                capture_output=True, text=True, check=False
            )
            if container_name in paused_check.stdout:
                logger.warning(f"Container {container_name} is PAUSED. To use it, run: docker unpause {container_name}")
            
            return False
        except Exception:
            return False

    def _add_nuclei_vuln(self, normalized: Dict[str, Any], data: Dict[str, Any]):
        if not isinstance(data, dict): return
        normalized["vulnerabilities"].append({
            "name": data.get("info", {}).get("name"),
            "severity": data.get("info", {}).get("severity", "informational").lower(),
            "description": data.get("info", {}).get("description"),
            "reference": data.get("info", {}).get("reference")
        })

    def normalize_output(self, scanner_name: str, raw_output: str, report_file: str | None = None) -> Dict[str, Any]:
        """
        Normalize output from Docker-based scanners.
        """
        normalized: Dict[str, Any] = {
            "scanner": scanner_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": []
        }

        if report_file and os.path.exists(report_path_str := str(report_file)):
            try:
                # ... (existing parsing logic)
                if scanner_name == "zap" and report_path_str.endswith(".json"):
                    with open(report_path_str, 'r') as f:
                        data = json.load(f)
                        site_data = data.get("site", [{}])
                        alerts = site_data[0].get("alerts", []) if site_data else []
                        for alert in alerts:
                            normalized["vulnerabilities"].append({
                                "name": alert.get("name"),
                                "severity": alert.get("riskdesc", "Informational").split(" ")[0].lower(),
                                "description": alert.get("desc"),
                                "solution": alert.get("solution")
                            })
                elif scanner_name == "nuclei" and report_path_str.endswith(".json"):
                    with open(report_path_str, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                if isinstance(data, list):
                                    for item in data:
                                        self._add_nuclei_vuln(normalized, item)
                                else:
                                    self._add_nuclei_vuln(normalized, data)
                            except Exception:
                                continue
                elif scanner_name == "nmap" and report_path_str.endswith(".xml"):
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(report_path_str)
                    root = tree.getroot()
                    for host in root.findall('host'):
                        for port in host.findall('.//port'):
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                service = port.find('service')
                                svc_name = service.get('name') if service is not None else "unknown"
                                severity = "medium"
                                port_id = int(port.get('portid', '0'))
                                if port_id in [22, 23, 1433, 3306, 5432]:
                                    severity = "high"
                                normalized["vulnerabilities"].append({
                                    "name": f"Open Port: {port_id}",
                                    "severity": severity,
                                    "description": f"Service {svc_name} is running on open port {port_id}",
                                    "solution": "Ensure this service is intended to be publicly exposed."
                                })
            except Exception as e:
                logger.error(f"Error parsing report for {scanner_name}: {e}")
                normalized["error"] = str(e)
        else:
             # Handle scanners that don't create files when 0 findings are found
            if scanner_name == "nuclei" and "No results found" in str(raw_output):
                 logger.info(f"Nuclei finished with 0 findings.")
            elif scanner_name == "nmap" and "0 hosts up" in str(raw_output):
                 logger.info(f"Nmap finished with 0 findings.")
            else:
                 raw_snap = str(raw_output)[:500]
                 normalized["error"] = f"Report file not created by scanner. Check scanner logs. Output snapshot: {raw_snap}"
                 normalized["raw_output"] = str(raw_output)[:1000]

        # Calculate totals
        vulns = normalized.get("vulnerabilities", [])
        normalized["total"] = len(vulns)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulns:
            sev = v.get("severity", "informational").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["informational"] += 1
        normalized["severity_breakdown"] = counts

        return normalized

    def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parallelized Run API: Supports concurrent hybrid (Docker + Python) execution.
        """
        scanners_to_run = params.get("scanners", [])
        target = params.get("target")

        if not target:
            raise ValueError("Target is required.")

        scan_id = str(uuid.uuid4())
        results: Dict[str, Any] = {
            "scan_id": scan_id,
            "target": target,
            "findings": {},
            "status": "completed"
        }

        # Pre-import Python scanners sequentially to avoid threading deadlocks during concurrent module loading
        import importlib
        for scanner in scanners_to_run:
            cap = self.CAPABILITY_MANIFEST.get(scanner, {})
            if cap.get("type") == "python":
                try:
                    importlib.import_module(cap["module"])
                except Exception as e:
                    logger.warning(f"Failed to pre-warm scanner {scanner}: {e}")

        # Use ThreadPoolExecutor for parallel execution
        max_workers = min(len(scanners_to_run), 5) if scanners_to_run else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_scanner = {
                executor.submit(self._run_single_scanner, scanner, target, scan_id): scanner 
                for scanner in scanners_to_run
            }
            
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    scanner_result = future.result()
                    results["findings"][scanner] = scanner_result
                    if isinstance(scanner_result, dict) and "error" in scanner_result:
                        results["status"] = "partial_failure"
                except Exception as e:
                    logger.error(f"Critical error in {scanner} execution thread: {e}")
                    results["findings"][scanner] = {"error": str(e)}
                    results["status"] = "partial_failure"

        # Run Correlation Engine (Sequential after all scanners finish)
        correlator = CorrelationEngine()
        results["correlated_findings"] = correlator.correlate(results)
        
        return results

    def _run_single_scanner(self, scanner: str, target: str, scan_id: str) -> Dict[str, Any]:
        """Internal helper to execute a single scanner and return normalized results."""
        try:
            if not self.is_scanner_available(scanner):
                return {"error": f"Scanner {scanner} is not available."}
            
            capabilities = self.CAPABILITY_MANIFEST[scanner]
            stype = capabilities.get("type")

            if stype == "python":
                logger.info(f"Running Python scanner: {scanner}")
                with self._import_lock:
                    module = importlib.import_module(capabilities["module"])
                
                scanner_class = getattr(module, capabilities["class"])
                scanner_instance = scanner_class()
                
                if hasattr(scanner_instance, "scan_directory") and os.path.isdir(target):
                    return scanner_instance.scan_directory(target)
                else:
                    return scanner_instance.scan(target)

            elif stype == "docker":
                logger.info(f"Running Docker scanner: {scanner} (Job: {str(scan_id)[:8]})")
                report_name = f"{scanner}_{scan_id}.json"
                if scanner == "nmap":
                    report_name = f"{scanner}_{scan_id}.xml"
                
                report_path = f"{self.output_dir}/{report_name}"
                cmd_template = str(capabilities.get("command_template", ""))
                base_container_name = capabilities.get("container_name")
                
                # Dynamic container naming to avoid conflicts
                unique_container_name = f"{base_container_name}_{str(scan_id)[:8]}"

                current_target = self._sanitize_target(target, scanner)
                
                import shlex
                import pathlib
                project_root = pathlib.Path(__file__).resolve().parent.parent
                abs_output_dir = os.path.abspath(self.output_dir)
                abs_templates_dir = os.path.abspath(project_root / "tmp" / "nuclei-templates")
                os.makedirs(abs_templates_dir, exist_ok=True)
                
                # For Docker, we always use 'run --rm' for the parallel POC to ensure clean isolation
                # We also inject the unique name to the container
                prefix = capabilities.get("run_prefix", "").format(
                    output_dir=abs_output_dir,
                    templates_dir=abs_templates_dir,
                    image=capabilities["image"]
                )
                
                # Insert the --name flag right after 'docker run'
                if prefix.startswith("docker run"):
                    prefix = prefix.replace("docker run", f"docker run --name {unique_container_name}")

                full_cmd = f"{prefix} {cmd_template}".format(
                    target=current_target,
                    report_name=report_name
                )
                
                cmd_args = shlex.split(full_cmd)
                try:
                    process = subprocess.run(cmd_args, capture_output=True, text=True, check=False, timeout=600)
                except subprocess.TimeoutExpired as e:
                    logger.error(f"Scanner {scanner} timed out after 600s")
                    # Force cleanup if timeout
                    subprocess.run(["docker", "rm", "-f", unique_container_name], capture_output=True)
                    return {"error": "Timeout expired", "raw_output": e.stdout if e.stdout else ""}
                
                # Relocation logic if scanner writes to default volume
                if not os.path.exists(report_path):
                    generic_report_path = project_root / "tmp" / "scans" / report_name
                    if generic_report_path.exists():
                        import shutil
                        shutil.move(str(generic_report_path), report_path)

                return self.normalize_output(
                    scanner, 
                    process.stdout + "\n" + process.stderr,
                    report_path
                )

        except Exception as e:
            logger.error(f"Error in _run_single_scanner ({scanner}): {e}")
            return {"error": str(e)}
        
        return {"error": "Unknown execution error"}

if __name__ == "__main__":
    # Simple test execution
    manager = ScannerManager()
    print("ZAP Available:", manager.is_scanner_available("zap"))
    print("Nuclei Available:", manager.is_scanner_available("nuclei"))
    
    # Example Single-Run API execution (assuming images are present or can be pulled)
    # result = manager.run({"scanners": ["zap"], "target": "https://example.com"})
    # print(json.dumps(result, indent=2))
