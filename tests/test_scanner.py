"""Tests for DORAChecker scanner — detection accuracy and gap computation."""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import DORAChecker
from tests.conftest import make_project


# ============================================================
# Helpers
# ============================================================

def _checker(tmp_path, files: dict) -> DORAChecker:
    make_project(tmp_path, files)
    return DORAChecker(str(tmp_path))


# ============================================================
# Third-party dependency detection (Art. 28, 31)
# ============================================================

class TestThirdPartyDetection:

    def test_detects_boto3(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "import boto3\ns3 = boto3.client('s3')"})
        result = c.scan_project()
        assert "AWS" in result["findings"]["third_party_dependencies"]

    def test_detects_stripe(self, tmp_path):
        c = _checker(tmp_path, {"pay.py": "import stripe\nstripe.PaymentIntent.create()"})
        result = c.scan_project()
        assert "Stripe" in result["findings"]["third_party_dependencies"]

    def test_detects_openai(self, tmp_path):
        c = _checker(tmp_path, {"ai.py": "import openai\nclient = openai.OpenAI()"})
        result = c.scan_project()
        assert "OpenAI" in result["findings"]["third_party_dependencies"]

    def test_detects_requests_http(self, tmp_path):
        c = _checker(tmp_path, {"client.py": "import requests\nresp = requests.get('https://api.example.com')"})
        result = c.scan_project()
        assert "requests (HTTP)" in result["findings"]["third_party_dependencies"]

    def test_detects_httpx(self, tmp_path):
        c = _checker(tmp_path, {"client.py": "import httpx\nclient = httpx.Client()"})
        result = c.scan_project()
        assert "httpx (HTTP)" in result["findings"]["third_party_dependencies"]

    def test_no_false_positives_clean_project(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "from flask import Flask\napp = Flask(__name__)\n"})
        result = c.scan_project()
        # Flask not in ICT third-party list
        deps = result["findings"]["third_party_dependencies"]
        assert "AWS" not in deps
        assert "Stripe" not in deps

    def test_empty_project_no_deps(self, tmp_path):
        c = _checker(tmp_path, {})
        result = c.scan_project()
        assert result["findings"]["third_party_dependencies"] == {}
        assert result["files_scanned"] == 0

    def test_multiple_vendors_detected(self, tmp_path):
        c = _checker(tmp_path, {
            "cloud.py": "import boto3\nfrom azure.storage.blob import BlobServiceClient",
            "pay.py": "import stripe",
        })
        result = c.scan_project()
        deps = result["findings"]["third_party_dependencies"]
        assert "AWS" in deps
        assert "Azure" in deps
        assert "Stripe" in deps


# ============================================================
# Mutable logging detection (Art. 10, 17)
# ============================================================

class TestMutableLoggingDetection:

    def test_detects_file_handler(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "import logging\nhandler = logging.FileHandler('app.log')"})
        result = c.scan_project()
        assert result["findings"]["mutable_logging"]

    def test_detects_basicconfig_filename(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "import logging\nlogging.basicConfig(filename='app.log', level=logging.INFO)"})
        result = c.scan_project()
        assert result["findings"]["mutable_logging"]

    def test_detects_file_append_mode(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "with open('events.log', 'a') as f:\n    f.write('event')"})
        result = c.scan_project()
        assert result["findings"]["mutable_logging"]

    def test_no_mutable_log_clean_project(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "print('hello')\nx = 1"})
        result = c.scan_project()
        assert result["findings"]["mutable_logging"] == []

    def test_detects_structured_logging_positive(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "import structlog\nlog = structlog.get_logger()"})
        result = c.scan_project()
        assert result["findings"]["has_structured_logging"] is True

    def test_loguru_counts_as_structured(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "from loguru import logger\nlogger.info('event')"})
        result = c.scan_project()
        assert result["findings"]["has_structured_logging"] is True


# ============================================================
# Retry / circuit breaker detection (Art. 11)
# ============================================================

class TestResilienceDetection:

    def test_detects_tenacity(self, tmp_path):
        c = _checker(tmp_path, {"retry.py": "from tenacity import retry\n@retry\ndef call(): pass"})
        result = c.scan_project()
        assert result["findings"]["has_retry"] is True

    def test_detects_backoff(self, tmp_path):
        c = _checker(tmp_path, {"retry.py": "import backoff\n@backoff.on_exception(backoff.expo, Exception)\ndef call(): pass"})
        result = c.scan_project()
        assert result["findings"]["has_retry"] is True

    def test_detects_circuit_breaker(self, tmp_path):
        c = _checker(tmp_path, {"cb.py": "import pybreaker\nbreaker = pybreaker.CircuitBreaker()"})
        result = c.scan_project()
        assert result["findings"]["has_circuit_breaker"] is True

    def test_no_retry_detected_plain_requests(self, tmp_path):
        c = _checker(tmp_path, {"client.py": "import requests\nrequests.get('https://api.example.com')"})
        result = c.scan_project()
        assert result["findings"]["has_retry"] is False

    def test_no_circuit_breaker_plain_project(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "x = 1"})
        result = c.scan_project()
        assert result["findings"]["has_circuit_breaker"] is False


# ============================================================
# Hardcoded credentials detection (Art. 9)
# ============================================================

class TestHardcodedCredentials:

    def test_detects_api_key_string(self, tmp_path):
        c = _checker(tmp_path, {"config.py": "api_key = 'sk-abc123def456ghi789jkl0'"})
        result = c.scan_project()
        assert result["findings"]["hardcoded_credentials"]

    def test_detects_aws_access_key(self, tmp_path):
        c = _checker(tmp_path, {"aws.py": "access_key = 'AKIAIOSFODNN7EXAMPLE'"})
        result = c.scan_project()
        assert result["findings"]["hardcoded_credentials"]

    def test_no_false_positive_env_var(self, tmp_path):
        c = _checker(tmp_path, {"config.py": "import os\napi_key = os.environ.get('API_KEY')"})
        result = c.scan_project()
        assert result["findings"]["hardcoded_credentials"] == []

    def test_detects_secrets_management_positive(self, tmp_path):
        c = _checker(tmp_path, {"config.py": "import os\ntoken = os.getenv('TOKEN')"})
        result = c.scan_project()
        assert result["findings"]["has_secrets_management"] is True


# ============================================================
# Security tests detection (Art. 24, 25)
# ============================================================

class TestSecurityTestsDetection:

    def test_detects_bandit_in_ci(self, tmp_path):
        c = _checker(tmp_path, {".github/workflows/ci.yml": "steps:\n  - run: bandit -r src/"})
        result = c.scan_project()
        assert result["findings"]["has_security_tests"] is True

    def test_detects_bandit_config(self, tmp_path):
        # Create .bandit config file in root
        (tmp_path / ".bandit").write_text("[bandit]\ntargets=src")
        c = DORAChecker(str(tmp_path))
        result = c.scan_project()
        assert result["findings"]["has_sast_config"] is True

    def test_no_security_tests_clean(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "x = 1"})
        result = c.scan_project()
        assert result["findings"]["has_security_tests"] is False
        assert result["findings"]["has_sast_config"] is False


# ============================================================
# Gap computation
# ============================================================

class TestGapComputation:

    def test_mutable_log_produces_critical_gap(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "import logging\nhandler = logging.FileHandler('app.log')"})
        result = c.scan_project()
        articles = [g["article"] for g in result["gaps"]]
        assert any("Art. 10" in a or "Art. 17" in a for a in articles)
        severities = [g["severity"] for g in result["gaps"]]
        assert "critical" in severities

    def test_hardcoded_cred_produces_critical_gap(self, tmp_path):
        c = _checker(tmp_path, {"cfg.py": "password = 'SuperSecret123abc'"})
        result = c.scan_project()
        articles = [g["article"] for g in result["gaps"]]
        assert any("Art. 9" in a for a in articles)

    def test_missing_retry_gap_only_with_http(self, tmp_path):
        """Missing retry gap should only appear if HTTP calls are present."""
        c = _checker(tmp_path, {"app.py": "x = 1"})
        result = c.scan_project()
        gap_keys = [g["gap"] for g in result["gaps"]]
        assert "missing_retry" not in gap_keys

    def test_missing_retry_gap_with_http(self, tmp_path):
        c = _checker(tmp_path, {"client.py": "import requests\nrequests.get('https://api.example.com')"})
        result = c.scan_project()
        gap_keys = [g["gap"] for g in result["gaps"]]
        assert "missing_retry" in gap_keys

    def test_ict_register_gap_with_deps(self, tmp_path):
        c = _checker(tmp_path, {"app.py": "import boto3"})
        result = c.scan_project()
        gap_keys = [g["gap"] for g in result["gaps"]]
        assert "ict_register_needed" in gap_keys

    def test_clean_project_minimal_gaps(self, tmp_path):
        """A project with structlog + os.environ + tenacity + no HTTP calls should have minimal gaps."""
        c = _checker(tmp_path, {
            "app.py": (
                "import structlog\n"
                "import os\n"
                "from tenacity import retry\n"
                "token = os.getenv('TOKEN')\n"
            ),
            ".bandit": "[bandit]\ntargets=src\n",
        })
        result = c.scan_project()
        # No hardcoded creds, structured logging, has retry, has security config
        # Only gaps should be organizational ones (not detectable from code)
        gap_keys = [g["gap"] for g in result["gaps"]]
        assert "hardcoded_credentials" not in gap_keys
        assert "mutable_logging" not in gap_keys

    def test_gap_trust_layer_relevant_flag(self, tmp_path):
        c = _checker(tmp_path, {"log.py": "logging.FileHandler('app.log')"})
        result = c.scan_project()
        tl_gaps = [g for g in result["gaps"] if g.get("trust_layer_relevant")]
        assert len(tl_gaps) >= 1
