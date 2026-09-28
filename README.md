# Project_Two - AI Security Intelligence Platform

**Project_Two** is an enterprise-grade **AI Security Intelligence Orchestrator** designed to transform fragmented security data into actionable, strategic intelligence. 

Unlike traditional vulnerability scanners that generate thousands of isolated alerts, Project_Two uses a **Hybrid Multi-Agent AI** architecture and a **RAG-powered Knowledge Base** to simulate the analytical workflow of expert security consultants.

---

## 1. Core Architecture

Project_Two bridges the gap between raw data and risk mitigation through three distinct layers:

### 🤖 Hybrid Multi-Agent AI (Amazon Bedrock)
The orchestrator uses a specialized 4-stage AI pipeline to analyze findings:
- **Vulnerability Agent (Investigator)**: Fast triage and classification using **Claude 3.5 Haiku**.
- **Remediation Agent (Fixer)**: Strategic architectural patches and de-biasing using **Claude 3.5 Sonnet**.
- **Threat Model Agent (Architect)**: Automated **STRIDE** analysis and trust boundary identification using **Claude 3.5 Haiku**.
- **Attack Graph Agent (Strategist)**: Generates chained JSON exploit paths and red-team scenarios using **Claude 3.5 Sonnet**.

### RAG Security Knowledge Base
A persistent vector store (**ChromaDB** / **AWS OpenSearch**) populated with 8+ authoritative sources:
- **NVD/CVE**, **CWE**, **MITRE ATT&CK**, **OWASP**, **ExploitDB**, and **Secure Coding Guides**.
- Agents are "Security-Aware"—retrieving real-world context before generating reports.

### Scan Correlation Engine
An internal intelligence layer that merges overlapping findings from multiple scanners (e.g., matching a ZAP alert with a Nuclei finding via CWE and location) to reduce redundancy and token consumption.

---

## 2. Platform Capabilities

Project_Two features a high-performance **Parallel Orchestration** engine and a **Premium Reporting** dashboard designed for executive and technical stakeholders.

### ⚡ Parallel Execution Engine
The orchestrator uses `ThreadPoolExecutor` to run multiple scanners simultaneously, reducing total scan time by up to 70%.
- **Docker-Based (DAST/Network)**: Concurrent execution of ZAP, Nuclei, and Nmap with unique container sandboxing.
- **Python-Based (SAST/SCA)**: Thread-safe analysis across Semgrep, Secrets, and Dependency modules.

### 📊 Premium Interactive Dashboards
A state-of-the-art reporting engine generates high-fidelity, interactive HTML dashboards for every scan.
- **Focused Intelligence**: Filter findings by severity and category in the premium report.
- **Attack Graph Visualization**: Embedded PNG diagrams of potential exploit paths.
- **Executive Metrics**: Visual risk scores, leak period analysis, and quality gate status.

---

## 3. Scanner Inventory

| Category | Scanner | Execution | Focus Area |
|:---|:---|:---|:---|
| **DAST** | **OWASP ZAP** | Docker | Web application vulnerability testing |
| **DAST** | **Nuclei** | Docker | Fast, template-based protocol scanning |
| **SAST** | **Semgrep** | Python | Static code analysis (65+ languages) with intelligent ruleset selector |
| **Secrets** | **Detect-Secrets** | Python | Credential, key, and token detection |
| **SCA** | **Pip-Audit** | Python | Dependency vulnerability (CVE) scanning |
| **Mobile** | **MobSF** | Hybrid | APK/IPA analysis via Docker API |
| **Binary** | **Desktop** | Python | Compiled binary analysis (PE, Mach-O, ELF) |
| **Network** | **Nmap** | Docker | Port scanning and service discovery |

> **Note on Mandiant CAPA Rules**: CAPA capability analysis works out-of-the-box using built-in binary rules. For extended vendor rules, clone [mandiant/capa-rules](https://github.com/mandiant/capa-rules) into `backend/scanners/capa-rules`.

---

## 4. Local Setup & Quick Start

### Prerequisites
- **Python 3.10+** & **Docker & Docker Compose**
- **AWS CLI** (Configured for Amazon Bedrock / Claude 3.5 access)

### Installation
1.  **Initialize Environment**:
    ```bash
    git clone <repository-url>
    cd Project_Two
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```
2.  **Initialize Dashboard**:
    ```bash
    uvicorn backend.dashboard.app:app --reload
    ```
    Live at: `http://127.0.0.1:8000`

### Local Testing
Run a unified parallel scan and generate a premium report:
```bash
# Web-parallel scan (ZAP + Nuclei)
python3 backend/run_poc_demo.py --target https://example.com --scanners zap,nuclei

# View reports
ls backend/reports/poc_demo/run_*/
```

---

## 5. Advanced Analytics (SonarQube-Inspired)

Project_Two implements professional SDLC security practices:
- **Leak Period Strategy**: Focus on "New" vulnerabilities introduced in the current development cycle.
- **Quality Gates**: Automated checks that fail the pipeline if new high-severity findings are detected.
- **Compliance Mapping**: All findings are automatically mapped to **OWASP Top 10**, **SANS Top 25**, and **CWE**.

---

## 6. AWS Production Roadmap

To transition this prototype into a production-grade enterprise platform, follow the [AWS Deployment Guide](AWS_DEPLOYMENT_GUIDE.md):
1.  **IAM & Roles**: Configure execution roles for Lambda and Bedrock Agents.
2.  **Storage & Persistence**: Setup **S3 buckets** for reports and **DynamoDB** for scan metadata.
3.  **Managed Intelligence**: Migrate from local ChromaDB to **Amazon OpenSearch Serverless**.
4.  **Compute Infrastructure**: Deploy the orchestrator to **AWS Lambda** and utilize **ECS/Fargate** for long-running scanner tasks.

---

## 7. Developer Guide: Python API

The `ScannerManager` provides a clean interface for integration into custom tools:

```python
from backend.orchestrator import ScannerManager

# Initialize with output directory
manager = ScannerManager(output_dir="./scans")

# Execute unified scan with correlation
params = {
    "scanners": ["semgrep", "secrets", "dependency"],
    "target": "/absolute/path/to/source_code"
}
results = manager.run(params)

# Inspect Correlated Findings
for finding in results['correlated_findings']:
    print(f"[{finding['severity']}] {finding['name']} - Found by: {finding['scanners']}")
```

### Standalone Scanner Usage
Each scanner can be used independently without the orchestrator:
```python
from backend.scanners.mobsf_scanner import MobSFScanner
from backend.scanners.desktop_scanner import DesktopBinaryScanner

# Mobile scan
mobile = MobSFScanner(api_url="http://localhost:8010")
results = mobile.scan("/path/to/app.ipa")

# Desktop binary scan
desktop = DesktopBinaryScanner()
results = desktop.scan("/path/to/app.exe")
```

---

## 8. Supporting Artifacts
- **[AWS Deployment Guide](AWS_DEPLOYMENT_GUIDE.md)**: Steps for cloud migration.
- **[Quick Start Guide](QUICKSTART.md)**: Fastest path to first scan.
- **[Security & Governance](SECURITY.md)**: Container security best practices.

---

## Contributing
Contributions are welcome. Please ensure all scanners support the **[comprehensive language list](backend/scanners/semgrep_scanner.py)** (65+ languages supported via Semgrep).

## License
This project is proprietary and confidential. Licensed for internal use only.
