# Quick Start: AI Security Intelligence Platform

This technical guide provides the fastest path to initializing the **Project_Two** platform and running your first AI-orchestrated security analysis.

---

## 1. Environment Initialization

### Prerequisites
- **Python 3.10+**
- **Docker & Docker Compose**
- **AWS CLI** (Configured with credentials having Amazon Bedrock access)

### Setup Commands
```bash
# 1. Clone & Enter
git clone <repository-url>
cd Project_Two

# 2. Virtual Environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Dependencies
pip install -r requirements.txt

# 4. AWS Configuration
aws configure
```

### Optional: Desktop Binary Analysis (CAPA)
For Windows/macOS binary analysis with MITRE ATT&CK mapping:
```bash
pip install flare-capa
# Or download standalone: https://github.com/mandiant/capa/releases
```

---

## 2. Initialize Security Intelligence (RAG)

Before running scans, populate the local vector store with authoritative security knowledge. This grounds the AI agents and prevents hallucinations.

```bash
# Ingest CVE, CWE, OWASP, MITRE, and Secure Coding datasets
python3 -m backend.knowledge_base.ingest_all
```

---

## 3. Running Your First Scan

### Launch Parallel Security Analysis
Project_Two identifies targets automatically (Hostnames, IPs, URLs, File Paths) and executes scanners in parallel for maximum efficiency.

```bash
# 1. Parallel Web-Security Scan (ZAP + Nuclei)
python3 backend/run_poc_demo.py --target https://example.com --scanners zap,nuclei

# 2. Parallel Code Security Scan (Semgrep + Secrets + Dependency)
python3 backend/run_poc_demo.py --target ./src --scanners semgrep,secrets,dependency

# 3. Mobile Security Scan (MobSF)
python3 backend/run_poc_demo.py --target /path/to/your_app.apk --scanners mobsf

# 4. Comprehensive Platform Integration Test
PYTHONPATH=. .venv/bin/pytest backend/test/test_all_scanners.py
```

---

## 4. Visualizing Results: Premium Dashboard

Project_Two generates interactive, high-fidelity security dashboards. Use the Central Command Dashboard to navigate historical runs and drill down into findings.

### Launch Dashboard
```bash
uvicorn backend.dashboard.app:app --reload
```
- **Access**: `http://127.0.0.1:8000`
- **Focused View**: The dashboard automatically displays the analysis for the most recent security scan.
- **Deep-Dive**: Click **"Open Interactive Report ↑"** to launch the high-fidelity D3/Tailwind-powered report for the current scan.

---

## 5. Available Scanners

| Scanner | Alias(es) | Type | Scans |
|:---|:---|:---|:---|
| Semgrep | `semgrep` | Python | Source code (65+ languages) |
| Secrets | `secrets` | Python | Hardcoded credentials |
| Dependency | `dependency` | Python | Known CVEs in packages |
| MobSF | `mobsf`, `apk` | Python/Docker | APK, IPA, XAPK files |
| Desktop Binary | `desktop`, `binary` | Python | EXE, DLL, Mach-O, ELF, .pkg |
| ZAP | `zap` | Docker | DAST web scanning (ghcr.io image) |
| Nuclei | `nuclei` | Docker | Vulnerability scanning (Optimized with -as) |
| Nmap | `nmap` | Docker | Network port scanning (Privileged) |

---

## 6. Verification & Output

### Scan Results
Correlated results are stored in `backend/reports/`. Each scan produces:
- **Raw findings**: Unfiltered output from each tool.
- **Correlated findings**: High-fidelity, de-duplicated results merged by the **Correlation Engine**.

### Advanced Features
- **Leak Period**: Compare against a baseline. The platform tags findings as `is_new: true/false`.
- **Quality Gates**: Fail the pipeline if new high-severity findings are detected.
- **Compliance Mapping**: Findings are mapped to **OWASP Top 10**, **SANS Top 25**, **CWE**, and **MITRE ATT&CK**.

---

## 7. MobSF Setup (Mobile Scanning)

To scan APK/IPA files with OWASP MobSF:
```bash
# Start MobSF container
docker run -it --rm -p 8010:8000 opensecurity/mobile-security-framework-mobsf:latest

# Get API key from MobSF home page → API DOCS
export MOBSF_API_KEY="your_key_here"

# Scan via orchestrator
python3 -c "
from backend.orchestrator import ScannerManager
m = ScannerManager()
r = m.run({'scanners': ['mobsf'], 'target': '/path/to/app.apk'})
print(r)
"
```

---

## 8. Deployment & Configuration

### CI/CD Integration
The platform is pre-configured for **GitLab CI/CD**. Every scan automatically outputs:
- `security_report.json`: For automated parsing and quality gates.
- `security_report.html`: For developer and executive review.
- `security_report.md`: For Git MR comments and documentation.

### AWS Scale-Out
For production workloads, refer to the **[AWS Deployment Guide](AWS_DEPLOYMENT_GUIDE.md)** to migrate to AWS Lambda and OpenSearch Serverless.
