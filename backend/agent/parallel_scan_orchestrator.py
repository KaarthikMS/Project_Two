import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.scanners.semgrep_scanner import SemgrepScanner
from backend.scanners.secrets_scanner import SecretsScanner
from backend.scanners.dependency_scanner import DependencyScanner
from backend.scanners.nmap_scanner import NmapScanner
from backend.scanners.nuclei_scanner import NucleiScanner
from backend.scanners.zap_scanner import ZAPScanner


logger = logging.getLogger(__name__)


class ParallelScanOrchestrator:

    def __init__(self):

        self.semgrep = SemgrepScanner()
        self.secrets = SecretsScanner()
        self.dependencies = DependencyScanner()

        self.nmap = NmapScanner()
        self.nuclei = NucleiScanner()
        self.zap = ZAPScanner()

    def run_repo_scans(self, repo_path):

        scanners = {
            "sast": lambda: self.semgrep.scan(repo_path),
            "secrets": lambda: self.secrets.scan(repo_path),
            "dependencies": lambda: self.dependencies.scan(repo_path),
        }

        return self._run_parallel(scanners)

    def run_web_scans(self, url):

        scanners = {
            "nuclei": lambda: self.nuclei.scan(url),
            "zap": lambda: self.zap.scan(url),
        }

        return self._run_parallel(scanners)

    def run_network_scan(self, target):

        scanners = {
            "nmap": lambda: self.nmap.scan(target)
        }

        return self._run_parallel(scanners)

    def run_full_scan(self, repo_path=None, url=None, target=None):

        results = {}

        if repo_path:
            results["repo_scans"] = self.run_repo_scans(repo_path)

        if url:
            results["web_scans"] = self.run_web_scans(url)

        if target:
            results["network_scans"] = self.run_network_scan(target)

        return results

    def _run_parallel(self, scanners):

        results = {}

        with ThreadPoolExecutor(max_workers=6) as executor:

            futures = {
                executor.submit(scanner): name
                for name, scanner in scanners.items()
            }

            for future in as_completed(futures):

                name = futures[future]

                try:
                    results[name] = future.result()
                except Exception as e:
                    logger.error("Scanner %s failed: %s", name, str(e))
                    results[name] = {"error": str(e)}

        return results