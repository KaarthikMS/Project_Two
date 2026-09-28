# AWS Production Deployment Guide: AI Security Intelligence Platform

This guide provides a comprehensive 12-step roadmap for deploying the **Project_Two** prototype into a production-grade, enterprise-ready AWS environment.

---

## 🚀 12-Step Deployment Roadmap

### 1. Enable Amazon Bedrock Models
Ensure your AWS account has access to the following foundation models in the Amazon Bedrock console:
- **Anthropic Claude 3.5 Sonnet v2** (for deep reasoning/remediation)
- **Anthropic Claude 3.5 Haiku** (for efficient triage)
- **Amazon Titan Embeddings V2** (for Knowledge Base vectors)

### 2. Configure AWS CLI
Install the AWS CLI and configure your local environment with administrative credentials:
```bash
aws configure
# Verify connectivity
aws bedrock list-foundation-models --region us-east-1
```

### 3. Create IAM Roles
Define execution roles for the Lambda controller and any Bedrock Agents:
- **Lambda Role**: Must have `bedrock:InvokeModel`, `s3:PutObject`, `dynamodb:PutItem`, and `logs:CreateLogGroup` permissions.
- **Agent Role**: Must have permissions to invoke the controller Lambda.

### 4. Create S3 Bucket
Initialize a dedicated bucket for storing raw scanner reports and Knowledge Base source files:
```bash
aws s3 mb s3://project-two-security-intelligence-<account-id>
```

### 5. Create DynamoDB Table
Create a table to track scan metadata, historical trends, and Quality Gate statuses (supporting Leak Period analysis):
- **Table Name**: `SecurityScanMetadata`
- **Partition Key**: `scan_id` (String)

### 6. Run Knowledge Ingestion
Populate the RAG Knowledge Base with authoritative security datasets into **ChromaDB** (or **Amazon OpenSearch Serverless** for production):
```bash
python3 -m backend.knowledge_base.ingest_all
```

### 7. Connect RAG Retrieval to Agents
Ensure your agents (`vulnerability_agent.py`, `remediation_agent.py`, `threat_model_agent.py`, `attack_graph_agent.py`) are initialized with the `Retriever` module to fetch real-time security context from the vector store.

### 8. Replace LLM Calls with Bedrock
Verify all agent implementations use the `boto3` Bedrock Runtime client and the specified model IDs (Claude 3.5 Sonnet v2 / Haiku).

### 9. Deploy Controller Lambda
Package the `backend/` directory and deploy it as an AWS Lambda function:
```bash
# Example packaging
cd backend
zip -r ../deployment_package.zip .
# Deploy via CLI or Console
aws lambda create-function --function-name SecurityController \
  --handler controller_lambda.handler.lambda_handler \
  --runtime python3.10 \
  --timeout 900 \
  --memory-size 1024 \
  --role [ROLE_ARN] \
  --zip-file fileb://deployment_package.zip
```

### 10. Create Bedrock Agent
In the Bedrock console, create an **AI-Security-Engineer Agent**. Provide the high-level instructions defining its persona as a professional security consultant.

### 11. Connect Action Group
Link the Bedrock Agent to your Lambda function via an **Action Group**. Upload the OpenAPI schema defining the `/scan` and `/retrieve` endpoints.

### 12. Run End-to-End Test
Verify the deployment by triggering a scan through the Bedrock Agent chat window:
*"Run a vulnerability scan on target.com and provide a correlated remediation report using the Knowledge Base."*

---

## 🛡️ Production Recommendations
- **Managed Vector Store**: Transition from local ChromaDB to **Amazon OpenSearch Serverless** for high availability.
- **Compute Scaling**: Move long-running Docker scanner executions (ZAP, Nuclei, Nmap) to **AWS ECS/Fargate** tasks to bypass Lambda's 15-minute timeout.
- **Mobile Scanning**: Deploy MobSF as a persistent ECS service. Configure `MOBSF_API_KEY` via AWS Secrets Manager.
- **Desktop Binary Analysis**: Install Mandiant CAPA on the Lambda layer or ECS task for ATT&CK-mapped binary analysis.
- **Data Encryption**: Enable KMS encryption for S3 buckets and DynamoDB tables.
- **Scanner Isolation**: Python-based scanners (Semgrep, Secrets, Dependency) can run directly in Lambda. Docker-based scanners require ECS/Fargate.
