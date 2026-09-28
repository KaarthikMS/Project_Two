# Project_Two - POC Demo Guide

This guide explains how to showcase the capabilities of Project_Two during a live Proof of Concept (POC) demonstration, both for self-scanning and scanning external repositories.

---

## 🏗️ 1. Setup & Preparation

Before starting the demo, ensure you have the environment ready:

1. **Terminal Open**: Be in the project root (`Project_Two`).
2. **Virtual Environment Active**:
   ```bash
   source .venv/bin/activate
   ```
3. **Knowledge Base Populated**: (Do this before the meeting so the RAG is ready)
   ```bash
   python3 -m backend.knowledge_base.ingest_all
   ```
4. **Docker Running** (Optional but recommended):
   If you plan to show Mobile (MobSF), Web (ZAP), or Network (Nmap) scanning, ensure Docker Desktop is running and start the services:
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

---

## 🚀 2. Scenario 1: The "Self Scan" (Quick Demo)

This is the fastest way to demonstrate the orchestrator. It uses the project's own backend code as the target.

**Command:**
```bash
# Run the unified integration test suite
PYTHONPATH=. .venv/bin/pytest backend/test/test_all_scanners.py
```

**What it shows the audience:**
- The unified target interface (no need to configure 5 different tools).
- The execution of Semgrep (SAST), Detect-Secrets, and Pip-Audit (Dependency).
- The **4-Stage AI Assessment Pipeline**: Triage, Remediation, Threat Modeling (STRIDE), and Attack Graph (Exploit Chains).
- The **Correlation Engine** condensing raw findings (e.g., 620 raw alerts down to 20 correlated issues).
- The automatic generation of Markdown + JSON reports and an Attack Graph.

---

## 🎯 3. Scenario 2: Scanning a Provided Repository (Live Challenge)

If the audience asks you to scan *their* repository or a popular vulnerable app like WebGoat, follow these steps.

**Step A: Clone the repository to a temporary folder**
```bash
git clone https://github.com/WebGoat/WebGoat.git /tmp/target_repo
```

**Step B: Run the demo against that folder**
```bash
python3 backend/run_poc_demo.py --target /tmp/target_repo
```

**What it shows the audience:**
- The platform is truly target-agnostic and can analyze arbitrary codebases instantly.

---

## 📱 4. Scenario 3: Targeted Scans (Mobile or Web)

You can demonstrate the flexibility of the orchestrator by picking specific scanners.

> [!IMPORTANT]
> **Placeholder Warning**: Commands like `/path/to/app.exe` are placeholders. Replace them with the actual path to your file (e.g., `/Users/yourname/Desktop/app.exe`). **Do NOT** type `/path/to/app.exe` literally.

**Mobile App Scan (Requires MobSF running in Docker):**
```bash
python3 backend/run_poc_demo.py --target /path/to/my_app.apk --scanners mobsf
```

**Desktop Binary Scan:**
```bash
python3 backend/run_poc_demo.py --target /path/to/app.exe --scanners desktop
```

**Web/Network Scan (Network targets auto-converted to HTTPS):**
```bash
python3 backend/run_poc_demo.py --target https://owasp.org/www-project-juice-shop/ --scanners nmap,zap,nuclei
```

---

## 📊 5. The "Wow Factor" - Premium Dashboards

After running the script, navigate to the Command Dashboard to showcase the high-fidelity results.

### Dashboard Access
```bash
uvicorn backend.dashboard.app:app --reload
```
- Open `http://127.0.0.1:8000` in your browser.

### What to show the audience:
1. **Intelligence Summary**: Show how the platform aggregates total vulnerabilities and provides an AI synthesis across all scanners.
2. **AI assessment Drill-Down**: 
   - Show the **STRIDE Threat Model** for architectural insights.
   - Show the **Exploit Chain JSON** for red-team scenario simulation.
   - Click **"Open Interactive Report ↑"** to launch the high-fidelity D3 visualization.
3. **Correlation Intelligence**: Point out findings de-duplicated from multiple scanners.

---

## ☁️ 6. AWS Scenario A Setup (Optional)

You can demonstrate the platform's cloud-native capabilities by configuring "Scenario A" (using AWS Bedrock for AI Analysis + deploying the orchestrator to AWS Lambda). The default deployment region is **`ap-south-1`** (Mumbai), while Bedrock inference runs in `us-east-1`.

### Option A: Automated Configuration (Recommended)
Run the automated setup script to instantly provision your S3 Bucket, DynamoDB Table, IAM Roles, and Lambda function:
```bash
./aws_poc_setup.sh
```

### Option B: Manual Configuration (AWS Console)
If you prefer to or need to provision the resources manually:

**1. Create S3 Bucket (Report Storage)**
- Go to S3 > **Create bucket**. Name it `project-two-reports-poc-<initials>-2026`. Region: `ap-south-1`.

**2. Create DynamoDB Table (Metadata)**
- Go to DynamoDB > **Create table**. Name: `ProjectTwo_ScanMetadata`. Partition key: `scan_id` (String). Set Capacity to **On-demand**.

**3. Create IAM Role**
- Go to IAM > **Roles** > **Create role** (Trusted entity: Lambda).
- Attach managed policy: `AWSLambdaBasicExecutionRole`.
- Create an inline policy allowing `bedrock:InvokeModel`, `s3:PutObject`, `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:GetItem` on `*`.
- Name the role `ProjectTwoLambdaExecutionRolePOC`.

**4. Package and Deploy Lambda**
```bash
cd backend
zip -rq ../deployment_package.zip . -x "tmp/*" -x "reports/*" -x "knowledge_base/chroma_db/*" -x "*/__pycache__/*"
```
- Go to Lambda > **Create function** (`SecurityControllerPOC`, Python 3.10, use the IAM Role).
- Upload the `.zip` file.
- Under **Configuration > Environment variables**, add `S3_BUCKET` (your bucket name) and `DYNAMO_TABLE` (`ProjectTwo_ScanMetadata`).
- Under **General configuration**, set Timeout to `15 min` and Memory to `1024 MB`.
