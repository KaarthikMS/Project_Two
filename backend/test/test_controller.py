"""
Test Controller Lambda - Verifies the main entry point and routing logic.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from controller_lambda.handler import lambda_handler

@pytest.fixture
def bedrock_event():
    return {
        "messageVersion": "1.0",
        "actionGroup": "SecurityScanners",
        "apiPath": "/scan/repo",
        "httpMethod": "POST",
        "requestBody": {
            "content": {
                "application/json": {
                    "properties": [
                        {"name": "repo_url", "value": "\"https://github.com/example/repo\""},
                        {"name": "scan_types", "value": "[\"sast\", \"secrets\"]"}
                    ]
                }
            }
        }
    }

def test_handler_repo_scan_routing(bedrock_event):
    with patch("controller_lambda.handler.RepoDownloader") as mock_repo, \
         patch("controller_lambda.handler.SemgrepScanner") as mock_semgrep, \
         patch("controller_lambda.handler.SecretsScanner") as mock_secrets:
        
        mock_repo.return_value.__enter__.return_value = "/tmp/fake-path"
        mock_semgrep.return_value.scan.return_value = {"vulnerabilities": []}
        mock_secrets.return_value.scan.return_value = {"vulnerabilities": []}
        
        response = lambda_handler(bedrock_event, None)
        
        assert response["response"]["httpStatusCode"] == 200
        body = json.loads(response["response"]["responseBody"]["application/json"]["body"])
        assert body["repo_url"] == "https://github.com/example/repo"
        assert "scan_id" in body

def test_handler_unknown_path():
    event = {
        "actionGroup": "SecurityScanners",
        "apiPath": "/invalid/path",
        "requestBody": {"content": {"application/json": {"properties": []}}}
    }
    response = lambda_handler(event, None)
    assert response["response"]["httpStatusCode"] == 400
    assert "Unknown API path" in response["response"]["responseBody"]["application/json"]["body"]
