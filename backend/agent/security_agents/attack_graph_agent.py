import json
import boto3

class AttackGraphAgent:

    def __init__(self):
        self.client = boto3.client("bedrock-runtime", region_name="ap-south-1")
        self.model_id = "apac.anthropic.claude-3-5-sonnet-20240620-v1:0"

    def analyze(self, scan_results):

        prompt = f"""
You are an expert Principal Security Architect and Red Team Lead specializing in advanced persistent threat (APT) modeling and attack path analysis.

### ROLE
Analyze the provided security scan results to identify complex multi-stage exploit chains and lateral movement opportunities. Your goal is to visualize how an attacker could pivot from an initial entry point to high-value assets.

### METHODOLOGY
1. **Initial Access**: Identify vulnerabilities that allow initial foothold.
2. **Privilege Escalation**: Look for flaws that enable higher-level permissions.
3. **Lateral Movement**: Map paths between services or network segments.
4. **Exfiltration/Impact**: Define the final objective (e.g., data theft, service disruption).

### FRAMEWORK ALIGNMENT
Reference **MITRE ATT&CK** techniques where applicable (e.g., T1190 for Exploit Public-Facing Application).

### OUTPUT REQUIREMENTS
Return a structured JSON object representing the attack graph.
- **nodes**: Unique vulnerabilities or assets involved.
- **edges**: The transition step (from -> to) with a description of the exploit/pivot.
- **risk_score**: A value from 1-10 reflecting the likelihood and impact of the chain.

### JSON SCHEMA
{{
  "nodes": [
    {{ "id": "node_id", "label": "Vulnerability/Asset Name", "type": "initial_access|lateral|impact" }}
  ],
  "edges": [
    {{ "from": "node_id_1", "to": "node_id_2", "technique": "MITRE ATT&CK ID", "description": "How the pivot occurs" }}
  ],
  "summary": "Brief executive summary of the critical path",
  "overall_risk_score": 8.5
}}

### SCAN RESULTS
{json.dumps(scan_results)[:10000]}
"""

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}]
        }

        response = self.client.invoke_model(
            modelId=self.model_id,
            body=json.dumps(body)
        )

        result = json.loads(response["body"].read())

        return result["content"][0]["text"]