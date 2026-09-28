import json
import boto3

class ThreatModelAgent:

    def __init__(self):
        self.client = boto3.client("bedrock-runtime", region_name="ap-south-1")
        self.model_id = "apac.anthropic.claude-3-haiku-20240307-v1:0"

    def analyze(self, scan_results):

        prompt = f"""
You are a Certified Threat Modeling Professional with expertise in secure software design and architectural risk assessment.

### ROLE
Analyze the provided security scan results to build a structured threat model. Focus on identifying systemic risks beyond individual vulnerabilities.

### METHODOLOGY (STRIDE)
Categorize threats using the **STRIDE** model:
- **S**poofing: Can an attacker impersonate a user or service?
- **T**ampering: Can data or code be modified?
- **R**epudiation: Can actions be performed without a trace?
- **I**nformation Disclosure: Can sensitive data be leaked?
- **D**enial of Service: Can the system be made unavailable?
- **E**levation of Privilege: Can standard users gain admin access?

### ANALYSIS REQUIREMENTS
1. **Entry Points & Trust Boundaries**: Identify where untrusted data enters the system.
2. **High-Value Assets**: Define what is at risk (e.g., PII, database credentials).
3. **Threat Scenarios**: Describe realistic attack narratives.
4. **Assumptions**: List any assumptions made about the environment.

### OUTPUT STRUCTURE
Structure your response into clear sections:
## 1. SCOPE AND ASSETS
## 2. TRUST BOUNDARY ANALYSIS
## 3. STRIDE THREAT ENUMERATION (Table format: Threat, Category, Impact, Priority)
## 4. MITIGATION STRATEGIES

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