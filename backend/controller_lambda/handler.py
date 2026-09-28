"""
Controller Lambda Handler - Routes Bedrock Agent action groups to the appropriate scanners.

This handler is the entry point for AWS Lambda when invoked by Amazon Bedrock Agent.
It dispatches to specialized security scanners based on the action requested.
"""

import json
import logging
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any




from scanners.semgrep_scanner import SemgrepScanner
from scanners.secrets_scanner import SecretsScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.zap_scanner import ZAPScanner
from scanners.desktop_scanner import DesktopBinaryScanner
from scanners.mobsf_scanner import MobSFScanner
from utils.repo_downloader import RepoDownloader
from reports.report_generator import ReportGenerator



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# In-memory scan result store (in production, use DynamoDB or S3)
_scan_results_store: dict[str, dict] = {}


def lambda_handler(event: dict, context: Any) -> dict:
    """
    Main Lambda entry point. Routes Bedrock Agent action group invocations
    to the appropriate scanner or report generator.

    Args:
        event: Bedrock Agent action group invocation event
        context: Lambda context object

    Returns:
        Bedrock Agent action group response
    """
    logger.info("Received event: %s", json.dumps(event, default=str))

    action_group = event.get("actionGroup", "")
    api_path = event.get("apiPath", "")
    http_method = event.get("httpMethod", "POST")
    request_body = _parse_request_body(event)

    try:
        result = _route_request(api_path, http_method, request_body)
        return _build_success_response(event, result)
    except ValueError as e:
        logger.warning("Validation error: %s", str(e))
        return _build_error_response(event, 400, str(e))
    except Exception as e:
        logger.error("Unhandled error: %s\n%s", str(e), traceback.format_exc())
        return _build_error_response(event, 500, f"Internal error: {str(e)}")


def _route_request(api_path: str, http_method: str, body: dict) -> dict:
    """Routes the request to the appropriate handler based on api_path."""
    routes = {
        "/scan/repo": _handle_repo_scan,
        "/scan/web": _handle_web_scan,
        "/scan/network": _handle_network_scan,
        "/report/generate": _handle_report_generation,
    }

    handler = routes.get(api_path)
    if not handler:
        raise ValueError(f"Unknown API path: {api_path}")

    return handler(body)


def _handle_repo_scan(body: dict) -> dict:
    """Download a git repository and run SAST, secrets, and dependency scans."""
    repo_url = body.get("repo_url")
    if not repo_url:
        raise ValueError("repo_url is required")

    branch = body.get("branch", "main")
    scan_types = body.get("scan_types", ["sast", "secrets", "dependencies"])

    scan_id = str(uuid.uuid4())
    results = {
        "scan_id": scan_id,
        "repo_url": repo_url,
        "branch": branch,
        "scan_types": scan_types,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "findings": {},
    }

    with RepoDownloader(repo_url, branch) as repo_path:
        if "sast" in scan_types:
            scanner = SemgrepScanner()
            results["findings"]["sast"] = scanner.scan(repo_path)

        if "secrets" in scan_types:
            scanner = SecretsScanner()
            results["findings"]["secrets"] = scanner.scan(repo_path)

        if "dependencies" in scan_types:
            scanner = DependencyScanner()
            results["findings"]["dependencies"] = scanner.scan(repo_path)

        if "binary" in scan_types:
            scanner = DesktopBinaryScanner()
            results["findings"]["binary"] = scanner.scan_directory(repo_path)

        if "apk" in scan_types:
            scanner = MobSFScanner()
            results["findings"]["apk"] = scanner.scan_directory(repo_path)

    results["completed_at"] = datetime.now(timezone.utc).isoformat()
    results["total_findings"] = _count_findings(results["findings"])
    
    _scan_results_store[scan_id] = results
    return results


def _handle_web_scan(body: dict) -> dict:
    """Run DAST scan against a web application using ZAP and Nuclei."""
    target_url = body.get("target_url")
    if not target_url:
        raise ValueError("target_url is required")

    scan_policy = body.get("scan_policy", "Default Policy")
    authenticated = body.get("authenticated", False)

    scan_id = str(uuid.uuid4())
    results = {
        "scan_id": scan_id,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "findings": {},
    }

    zap_scanner = ZAPScanner()
    results["findings"]["zap"] = zap_scanner.scan(
        target_url, scan_policy=scan_policy, authenticated=authenticated
    )

    nuclei_scanner = NucleiScanner()
    results["findings"]["nuclei"] = nuclei_scanner.scan(target_url)

    results["completed_at"] = datetime.now(timezone.utc).isoformat()
    results["total_findings"] = _count_findings(results["findings"])
    _scan_results_store[scan_id] = results
    return results


def _handle_network_scan(body: dict) -> dict:
    """Run Nmap network scan against a target."""
    target = body.get("target")
    if not target:
        raise ValueError("target is required")

    ports = body.get("ports", "1-1024")
    scan_type = body.get("scan_type", "syn")

    scan_id = str(uuid.uuid4())
    scanner = NmapScanner()
    findings = scanner.scan(target, ports=ports, scan_type=scan_type)

    results = {
        "scan_id": scan_id,
        "target": target,
        "ports": ports,
        "scan_type": scan_type,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    _scan_results_store[scan_id] = results
    return results


def _handle_report_generation(body: dict) -> dict:

    """Generate a security report from stored scan results."""
    scan_ids = body.get("scan_ids", [])
    if not scan_ids:
        raise ValueError("scan_ids is required and must not be empty")

    report_format = body.get("format", "json")
    include_remediation = body.get("include_remediation", True)

    all_results = []
    missing_ids = []
    for scan_id in scan_ids:
        if scan_id in _scan_results_store:
            all_results.append(_scan_results_store[scan_id])
        else:
            missing_ids.append(scan_id)

    if missing_ids:
        logger.warning("Scan IDs not found: %s", missing_ids)

    generator = ReportGenerator()
    report = generator.generate(
        scan_results=all_results,
        report_format=report_format,
        include_remediation=include_remediation,
    )
    return report


def _count_findings(findings_dict: dict) -> dict:
    """Count findings by severity across all scanner results."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for scanner_name, scanner_findings in findings_dict.items():
        if isinstance(scanner_findings, dict) and "vulnerabilities" in scanner_findings:
            for vuln in scanner_findings["vulnerabilities"]:
                severity = vuln.get("severity", "informational").lower()
                if severity in counts:
                    counts[severity] += 1
    return counts


def _parse_request_body(event: dict) -> dict:
    """Extract and parse the request body from the Bedrock Agent event."""
    try:
        request_body = event.get("requestBody", {})
        content = request_body.get("content", {})
        app_json = content.get("application/json", {})
        properties = app_json.get("properties", [])

        # Convert Bedrock's property list format to a plain dict
        body = {}
        for prop in properties:
            name = prop.get("name")
            value = prop.get("value")
            try:
                body[name] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                body[name] = value
        return body
    except Exception:
        return {}


def _build_success_response(event: dict, result: dict) -> dict:
    """Build a successful Bedrock Agent action group response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", ""),
            "apiPath": event.get("apiPath", ""),
            "httpMethod": event.get("httpMethod", "POST"),
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(result, default=str)
                }
            },
        },
    }


def _build_error_response(event: dict, status_code: int, message: str) -> dict:
    """Build an error Bedrock Agent response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", ""),
            "apiPath": event.get("apiPath", ""),
            "httpMethod": event.get("httpMethod", "POST"),
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps({"error": message})
                }
            },
        },
    }
