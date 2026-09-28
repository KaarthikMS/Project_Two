import json
import boto3
import logging
from typing import Any, Dict

from backend.knowledge_base.retrieval.retriever import Retriever

logger = logging.getLogger(__name__)

class RemediationAgent:

    def __init__(self):
        self.client = boto3.client("bedrock-runtime", region_name="ap-south-1")
        self.model_id = "apac.anthropic.claude-3-5-sonnet-20240620-v1:0"
        self.retriever = Retriever()

    def analyze(self, scan_results):
        # Retrieve secure coding guides and remediation best practices
        vulnerability_summary = str(scan_results)[:1000]
        security_kb_context = self.retriever.retrieve_context(vulnerability_summary)

        prompt = f"""
You are a Senior Principal Software Engineer and DevSecOps Specialist with deep expertise in secure coding and infrastructure hardening.

### ROLE
Analyze the provided vulnerability scan results and provide comprehensive, actionable remediation guidance. Your recommendations must be prioritized by risk and practicality for a production environment.

### SECURE CODING GUIDELINES (RAG)
Use the following authoritative remediation patterns and secure coding guides to provide precise fixes:
{security_kb_context}

### REMEDIATION COMPARTMENTS
1. **Immediate Action**: Critical fixes to block active exploitation (e.g., firewall rules, disabling features).
2. **Short-term Fixes**: Code-level changes, dependency upgrades, or configuration adjustments.
3. **Long-term Strategy**: Architectural improvements, security training, or enhanced monitoring consistent with **OWASP Proactive Controls**.

### GUIDANCE REQUIREMENTS
For each critical finding, provide:
- **Technical Root Cause**: A brief explanation of why the vulnerability exists.
- **Remediation Steps**: Step-by-step instructions for developers.
- **Code Snippets**: Provide specific examples of secure code (e.g., using parameterized queries instead of string concatenation).
- **Configuration Examples**: Provide hardened configuration snippets (e.g., YAML for Kubernetes, JSON for AWS IAM).

### OUTPUT STRUCTURE
Structure your response into clear sections:
# EXECUTIVE SUMMARY
# CRITICAL FINDINGS & REMEDIATION
# STRATEGIC SYSTEM HARDENING
# REFERENCES (e.g., CVE IDs, OWASP Top 10)

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

    def generate_file_fix(self, vulnerability: Dict[str, Any], current_content: str) -> Dict[str, Any]:
        """
        Generate a full-file fix for a specific vulnerability.
        Returns a JSON object with the corrected code.
        """
        prompt = f"""
You are a Senior Security Engineer. Your task is to fix a security vulnerability in the provided source code.

### VULNERABILITY DETAILS
- **Rule ID**: {vulnerability.get('rule_id')}
- **Category**: {vulnerability.get('category' or 'security')}
- **Issue**: {vulnerability.get('message') or vulnerability.get('description')}
- **File**: {vulnerability.get('file')}
- **Line**: {vulnerability.get('line')}

### CURRENT SOURCE CODE
```python
{current_content}
```

### INSTRUCTIONS
1. Analyze the vulnerability and the surrounding code.
2. Provide the COMPLETELY FIXED version of the file.
3. Ensure the fix follows secure coding best practices (OWASP/SANS).
4. DO NOT change the logic of the application, only the security aspect.
5. Return your response in STRICT JSON format:
{{
  "explanation": "Brief description of what you fixed",
  "fixed_content": "The full content of the file after the fix"
}}

RESPONSE:
"""

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body)
            )
            raw_result = json.loads(response["body"].read())
            text_resp = raw_result["content"][0]["text"]
            
            # Extract JSON from potential markdown wrappers
            if "```json" in text_resp:
                text_resp = text_resp.split("```json")[1].split("```")[0].strip()
            
            return json.loads(text_resp)
        except Exception as e:
            logger.error(f"Failed to generate file fix: {e}")
            return {"error": str(e)}