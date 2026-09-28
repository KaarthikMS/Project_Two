from backend.agent.parallel_scan_orchestrator import ParallelScanOrchestrator
from backend.utils.repo_downloader import RepoDownloader


if __name__ == "__main__":
    repo = "https://github.com/juice-shop/juice-shop"
    
    orch = ParallelScanOrchestrator()
    
    with RepoDownloader(repo) as path:
    
        results = orch.run_full_scan(
            repo_path=path,
            url="http://demo.testfire.net",
            target="127.0.0.1"
        )
    
    print(results)