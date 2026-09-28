import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from backend.knowledge_base.ingestion.owasp_loader import OWASPLoader
from backend.knowledge_base.ingestion.mitre_loader import MITRELoader
from backend.knowledge_base.ingestion.cve_loader import CVELoader
from backend.knowledge_base.ingestion.cwe_loader import CWELoader
from backend.knowledge_base.ingestion.nvd_loader import NVDLoader
from backend.knowledge_base.ingestion.exploitdb_loader import ExploitDBLoader
from backend.knowledge_base.ingestion.cloud_rules_loader import CloudRulesLoader
from backend.knowledge_base.ingestion.guides_loader import GuidesLoader

def run_comprehensive_ingestion():
    print("🚀 Starting Comprehensive Security Knowledge Ingestion...")

    # 1. OWASP Top 10
    owasp_loader = OWASPLoader()
    owasp_loader.load_data([
        {"title": "Broken Access Control", "category": "OWASP A01:2021", "content": "Restrictions on what authenticated users are allowed to do are not properly enforced."}
    ])

    # 2. MITRE ATT&CK
    mitre_loader = MITRELoader()
    mitre_loader.load_techniques([
        {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."}
    ])

    # 3. CVE
    cve_loader = CVELoader()
    cve_loader.load_cve([
        {"id": "CVE-2023-32315", "severity": "High", "description": "A path traversal vulnerability in Openfire allows an unauthenticated user to access restricted pages."}
    ])

    # 4. CWE
    cwe_loader = CWELoader()
    cwe_loader.load_cwe([
        {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page."}
    ])

    # 5. NVD
    nvd_loader = NVDLoader()
    nvd_loader.load_nvd([
        {"cve_id": "CVE-2021-44228", "cvss": 10.0, "summary": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP...", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]}
    ])

    # 6. ExploitDB
    exploit_loader = ExploitDBLoader()
    exploit_loader.load_exploits([
        {"id": "EDB-ID-51000", "title": "Log4j JNDI Remote Code Execution", "platform": "Java", "description": "Exploit for CVE-2021-44228 targeting various Java applications."}
    ])

    # 7. Cloud Misconfiguration
    cloud_loader = CloudRulesLoader()
    cloud_loader.load_rules([
        {"provider": "AWS", "service": "S3", "title": "S3 Bucket Public Access", "remediation": "Enable block public access settings for the S3 bucket."}
    ])

    # 8. Secure Coding Guides
    guides_loader = GuidesLoader()
    guides_loader.load_guides([
        {"language": "Python", "category": "Injection", "content": "Always use parameterized queries or ORMs. Never use f-strings or string concatenation for SQL queries."}
    ])

    print("✅ Comprehensive Ingestion Completed Successfully!")

if __name__ == "__main__":
    run_comprehensive_ingestion()
