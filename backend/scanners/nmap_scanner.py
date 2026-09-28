"""
Nmap Scanner - Network Port Scanning and Service Detection.

Wraps the python-nmap library to perform:
- TCP SYN/Connect scanning
- Service version detection
- OS fingerprinting
- SSL/TLS certificate analysis
- Script scanning (CVE checks, default credentials)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    Network vulnerability scanner using Nmap.

    Performs:
    - Port scanning (SYN, connect, UDP)
    - Service/version detection
    - OS fingerprinting
    - NSE script execution (vuln category, ssl-*, etc.)
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "syn",
    ) -> dict[str, Any]:
        """
        Perform network scan on a target.

        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range string (e.g., "22,80,443" or "1-1024")
            scan_type: "syn", "connect", or "udp"

        Returns:
            Dict with open ports, services, and vulnerability findings
        """
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            target = urlparse(target).netloc
        
        logger.info("Starting Nmap scan on %s (ports: %s, type: %s)", target, ports, scan_type)

        try:
            import nmap  # type: ignore
            return self._run_nmap(target, ports, scan_type, nmap)
        except ImportError:
            return self._error_result("python-nmap not installed. Real scan cannot proceed.")

    def _run_nmap(self, target: str, ports: str, scan_type: str, nmap: Any) -> dict[str, Any]:
        """Execute Nmap scan using python-nmap."""
        nm = nmap.PortScanner()

        # Build scan arguments
        nmap_args = self._build_args(scan_type)

        try:
            nm.scan(hosts=target, ports=ports, arguments=nmap_args, timeout=self.timeout)
        except nmap.PortScannerError as e:
            logger.error("Nmap scan failed: %s", str(e))
            return self._error_result(f"Nmap scan failed: {e}")
        hosts_results = []
        vulnerabilities = []

        for host in nm.all_hosts():
            host_info = self._parse_host(nm, host)
            hosts_results.append(host_info)
            vulnerabilities.extend(self._extract_vulnerabilities(host_info))

        return {
            "scanner": "nmap",
            "target": target,
            "ports": ports,
            "scan_type": scan_type,
            "hosts": hosts_results,
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity_breakdown": self._count_by_severity(vulnerabilities),
        }

    def _build_args(self, scan_type: str) -> str:
        """Build Nmap argument string based on scan type."""
        base_args = "-sV --version-intensity 5"  # service version detection
        script_args = "--script=vuln,ssl-enum-ciphers,ssl-cert,http-security-headers"

        if scan_type == "syn":
            return f"-sS {base_args} {script_args}"
        elif scan_type == "connect":
            return f"-sT {base_args} {script_args}"
        elif scan_type == "udp":
            return f"-sU {base_args}"
        else:
            return f"-sT {base_args} {script_args}"

    def _parse_host(self, nm: Any, host: str) -> dict:
        """Parse Nmap scan results for a single host."""
        host_data = nm[host]
        open_ports = []

        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                port_data = host_data[proto][port]
                if port_data["state"] == "open":
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extra_info": port_data.get("extrainfo", ""),
                        "cpe": port_data.get("cpe", ""),
                        "scripts": self._parse_scripts(port_data.get("script", {})),
                    }
                    open_ports.append(port_info)

        return {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "os_guess": self._get_os_guess(nm, host),
            "open_ports": open_ports,
        }

    def _get_os_guess(self, nm: Any, host: str) -> str:
        """Get the OS fingerprint guess for a host."""
        try:
            osmatch = nm[host].get("osmatch", [])
            if osmatch:
                return f"{osmatch[0]['name']} ({osmatch[0]['accuracy']}%)"
        except (KeyError, IndexError):
            pass
        return "unknown"

    def _parse_scripts(self, scripts: dict) -> list[dict]:
        """Parse NSE script output."""
        results = []
        for script_name, output in scripts.items():
            results.append({
                "script": script_name,
                "output": str(output)[:500],  # truncate long output
            })
        return results

    def _extract_vulnerabilities(self, host_info: dict) -> list[dict]:
        """Extract security findings from parsed host data."""
        vulnerabilities = []
        host = host_info["host"]

        for port_info in host_info.get("open_ports", []):
            port = port_info["port"]
            service = port_info["service"]

            # Check for dangerous services
            dangerous_services = {
                23: ("telnet", "critical", "Telnet transmits data in plaintext including credentials"),
                21: ("ftp", "high", "FTP may allow anonymous login or transmit credentials in plaintext"),
                69: ("tftp", "high", "TFTP has no authentication"),
                161: ("snmp", "medium", "SNMP v1/v2 uses community strings with no encryption"),
                512: ("rexec", "critical", "rexec transmits credentials in plaintext"),
                513: ("rlogin", "critical", "rlogin has weak authentication"),
                514: ("rsh", "critical", "rsh executes commands without strong authentication"),
            }

            if port in dangerous_services:
                svc_name, severity, description = dangerous_services[port]
                vulnerabilities.append({
                    "severity": severity,
                    "host": host,
                    "port": port,
                    "service": svc_name,
                    "description": description,
                    "cwe": "CWE-319",
                    "recommendation": f"Disable {svc_name} and use a secure alternative (SSH, SFTP)",
                    "scanner": "nmap",
                })

            # Check script output for vulnerabilities
            for script_result in port_info.get("scripts", []):
                if "VULNERABLE" in script_result.get("output", ""):
                    vulnerabilities.append({
                        "severity": "high",
                        "host": host,
                        "port": port,
                        "service": service,
                        "description": f"Nmap script detected vulnerability: {script_result['script']}",
                        "script_output": script_result["output"][:300],
                        "cwe": "CWE-1188",
                        "recommendation": "Patch the affected service or apply vendor mitigations",
                        "scanner": "nmap",
                    })

            # Check for weak SSL/TLS ciphers
            for script_result in port_info.get("scripts", []):
                if "ssl-enum-ciphers" in script_result.get("script", ""):
                    output = script_result.get("output", "")
                    if "TLSv1.0" in output or "TLSv1.1" in output or "SSLv" in output:
                        vulnerabilities.append({
                            "severity": "medium",
                            "host": host,
                            "port": port,
                            "service": service,
                            "description": "Deprecated TLS version supported (TLS 1.0/1.1 or SSL)",
                            "cwe": "CWE-326",
                            "recommendation": "Configure server to support only TLS 1.2 and TLS 1.3",
                            "scanner": "nmap",
                        })

        return vulnerabilities


    def _count_by_severity(self, vulnerabilities: list[dict]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _error_result(self, message: str) -> dict:
        return {
            "scanner": "nmap",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }
