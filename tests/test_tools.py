"""Tests for MCP tools — paywall, banner, ICT register, incident template, report, rate limiter."""

import sys
import json
import time
import pytest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    DORAChecker,
    RateLimiter,
    ApiKeyManager,
    _require_plan,
    _add_banner,
    _current_plan,
    _scan_remaining,
    FREE_TIER_DAILY_LIMIT,
    TRUST_LAYER_CTA,
    _PRICING_URL,
)
from tests.conftest import make_project


# ============================================================
# RateLimiter
# ============================================================

class TestRateLimiter:

    def test_first_request_allowed(self):
        rl = RateLimiter()
        allowed, remaining = rl.check("1.2.3.4")
        assert allowed is True
        assert remaining == FREE_TIER_DAILY_LIMIT - 1

    def test_limit_reached(self):
        rl = RateLimiter()
        for _ in range(FREE_TIER_DAILY_LIMIT):
            rl.check("10.0.0.1")
        allowed, remaining = rl.check("10.0.0.1")
        assert allowed is False
        assert remaining == 0

    def test_different_ips_independent(self):
        rl = RateLimiter()
        rl._clients["99.99.99.99"] = {"date": "2020-01-01", "count": FREE_TIER_DAILY_LIMIT}
        allowed, _ = rl.check("1.1.1.1")
        assert allowed is True

    def test_date_reset(self):
        rl = RateLimiter()
        rl._clients["5.5.5.5"] = {"date": "2020-01-01", "count": FREE_TIER_DAILY_LIMIT}
        allowed, _ = rl.check("5.5.5.5")
        assert allowed is True

    def test_cleanup_removes_stale(self):
        rl = RateLimiter()
        rl._clients["old"] = {"date": "2000-01-01", "count": 5}
        rl._clients["new"] = {"date": "9999-01-01", "count": 5}
        rl._last_cleanup = time.time() - RateLimiter._CLEANUP_INTERVAL - 1
        rl.check("trigger.cleanup")
        assert "old" not in rl._clients

    def test_persistence(self, tmp_path):
        path = tmp_path / "limits.json"
        RateLimiter._PERSIST_PATH = path
        rl = RateLimiter()
        rl.check("persist.me")
        assert path.exists()
        data = json.loads(path.read_text())
        assert "persist.me" in data


# ============================================================
# ApiKeyManager
# ============================================================

class TestApiKeyManager:

    def test_missing_file_no_crash(self, tmp_path):
        mgr = ApiKeyManager(tmp_path / "nonexistent.json")
        assert mgr.verify("any") is None

    def test_verify_valid_key(self, tmp_path):
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "ak_test123", "plan": "pro", "active": True}]
        }))
        mgr = ApiKeyManager(keys_file)
        result = mgr.verify("ak_test123")
        assert result is not None
        assert result["plan"] == "pro"

    def test_inactive_key_rejected(self, tmp_path):
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "ak_inactive", "plan": "pro", "active": False}]
        }))
        mgr = ApiKeyManager(keys_file)
        assert mgr.verify("ak_inactive") is None

    def test_corrupted_json_no_crash(self, tmp_path):
        keys_file = tmp_path / "keys.json"
        keys_file.write_text("{corrupted")
        mgr = ApiKeyManager(keys_file)
        assert mgr.verify("any") is None

    def test_reload_after_cache_expiry(self, tmp_path):
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({"keys": []}))
        mgr = ApiKeyManager(keys_file)
        mgr._loaded_at = time.time() - 61
        # Add a key after initial load
        keys_file.write_text(json.dumps({
            "keys": [{"key": "ak_new", "plan": "certified", "active": True}]
        }))
        result = mgr.verify("ak_new")
        assert result is not None


# ============================================================
# Paywall: _require_plan
# ============================================================

class TestRequirePlan:

    def test_free_can_access_free_tool(self):
        token = _current_plan.set("free")
        try:
            gate = _require_plan("free", "scan_project")
            assert gate is None
        finally:
            _current_plan.reset(token)

    def test_free_blocked_from_pro_tool(self):
        token = _current_plan.set("free")
        try:
            gate = _require_plan("pro", "generate_ict_register")
            assert gate is not None
            assert gate["upgrade_required"] is True
            assert "Pro" in gate["required_plan"]
            assert "upgrade_url" in gate
        finally:
            _current_plan.reset(token)

    def test_pro_can_access_pro_tool(self):
        token = _current_plan.set("pro")
        try:
            gate = _require_plan("pro", "generate_ict_register")
            assert gate is None
        finally:
            _current_plan.reset(token)

    def test_pro_blocked_from_certified_tool(self):
        token = _current_plan.set("pro")
        try:
            gate = _require_plan("certified", "certify_report")
            assert gate is not None
            assert "Certified" in gate["required_plan"]
        finally:
            _current_plan.reset(token)

    def test_certified_can_access_all(self):
        token = _current_plan.set("certified")
        try:
            assert _require_plan("free", "scan_project") is None
            assert _require_plan("pro", "generate_ict_register") is None
            assert _require_plan("certified", "certify_report") is None
        finally:
            _current_plan.reset(token)


# ============================================================
# Banner: _add_banner
# ============================================================

class TestAddBanner:

    def test_free_tier_adds_upgrade_key(self):
        token = _current_plan.set("free")
        remaining_token = _scan_remaining.set(5)
        try:
            result = _add_banner({"findings": {}})
            assert "upgrade" in result
            assert _PRICING_URL in result["upgrade"]
        finally:
            _current_plan.reset(token)
            _scan_remaining.reset(remaining_token)

    def test_free_last_scan_warning(self):
        token = _current_plan.set("free")
        remaining_token = _scan_remaining.set(1)
        try:
            result = _add_banner({"findings": {}})
            assert "Last free scan" in result["upgrade"] or "1" in result["upgrade"]
        finally:
            _current_plan.reset(token)
            _scan_remaining.reset(remaining_token)

    def test_pro_adds_trust_layer_cta(self):
        token = _current_plan.set("pro")
        try:
            result = _add_banner({"findings": {}})
            assert "trust_layer" in result
            assert "arkforge.tech/trust" in result["trust_layer"]
        finally:
            _current_plan.reset(token)

    def test_mutable_logging_triggers_trust_layer_gaps_cta(self):
        token = _current_plan.set("free")
        remaining_token = _scan_remaining.set(5)
        try:
            result = _add_banner({
                "findings": {"mutable_logging": ["app.py"]},
            })
            assert "trust_layer" in result
            assert "tamper-proof" in result["trust_layer"].lower() or "Trust Layer" in result["trust_layer"]
        finally:
            _current_plan.reset(token)
            _scan_remaining.reset(remaining_token)


# ============================================================
# DORAChecker: generate_ict_register
# ============================================================

class TestGenerateIctRegister:

    def test_register_contains_detected_vendors(self, tmp_path):
        make_project(tmp_path, {"app.py": "import boto3\nimport stripe"})
        c = DORAChecker(str(tmp_path))
        c.scan_project()
        register = c.generate_ict_register()
        vendor_names = [e["provider_name"] for e in register["register"]]
        assert "AWS" in vendor_names
        assert "Stripe" in vendor_names

    def test_register_aws_classified_critical(self, tmp_path):
        make_project(tmp_path, {"app.py": "import boto3"})
        c = DORAChecker(str(tmp_path))
        c.scan_project()
        register = c.generate_ict_register()
        aws_entry = next(e for e in register["register"] if e["provider_name"] == "AWS")
        assert aws_entry["classification"] == "critical"

    def test_register_mandatory_fields_present(self, tmp_path):
        make_project(tmp_path, {"app.py": "import boto3"})
        c = DORAChecker(str(tmp_path))
        c.scan_project()
        register = c.generate_ict_register()
        for entry in register["register"]:
            assert "provider_name" in entry
            assert "service_type" in entry
            assert "classification" in entry
            assert "sla_defined" in entry
            assert "audit_rights_in_contract" in entry
            assert "data_location_eu" in entry
            assert "exit_strategy_documented" in entry

    def test_register_no_deps_empty(self, tmp_path):
        make_project(tmp_path, {"app.py": "x = 1"})
        c = DORAChecker(str(tmp_path))
        c.scan_project()
        register = c.generate_ict_register()
        assert register["providers_detected"] == 0
        assert register["register"] == []

    def test_register_article_label(self, tmp_path):
        make_project(tmp_path, {})
        c = DORAChecker(str(tmp_path))
        register = c.generate_ict_register()
        assert "Art. 31" in register["article"]


# ============================================================
# DORAChecker: generate_incident_template
# ============================================================

class TestGenerateIncidentTemplate:

    def test_template_has_classification_framework(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        template = c.generate_incident_template()
        assert "classification_framework" in template
        cf = template["classification_framework"]
        assert "major" in cf
        assert "significant" in cf
        assert "minor" in cf

    def test_major_incident_has_reporting_deadlines(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        template = c.generate_incident_template()
        major = template["classification_framework"]["major"]
        deadlines = major["reporting_deadlines"]
        assert "4" in deadlines["initial_notification"]
        assert "72" in deadlines["intermediate_report"]
        assert "1 month" in deadlines["final_report"]

    def test_template_has_incident_record(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        template = c.generate_incident_template()
        record = template["incident_record_template"]
        assert "incident_id" in record
        assert "classification" in record
        assert "detected_at" in record

    def test_template_trust_layer_note(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        template = c.generate_incident_template()
        assert "Trust Layer" in template["immutability_note"]
        assert "Art. 17" in template["immutability_note"]

    def test_template_has_article_label(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        template = c.generate_incident_template()
        assert "Art. 17" in template["article"]


# ============================================================
# DORAChecker: generate_report
# ============================================================

class TestGenerateReport:

    def test_report_structure(self, tmp_path):
        make_project(tmp_path, {"app.py": "x = 1"})
        c = DORAChecker(str(tmp_path))
        scan = c.scan_project()
        report = c.generate_report(scan)
        assert report["report_type"] == "DORA Compliance Report"
        assert "combined_score_pct" in report
        assert "readiness" in report
        assert "recommendations" in report
        assert "next_steps" in report

    def test_report_with_org_assessment(self, tmp_path):
        make_project(tmp_path, {})
        c = DORAChecker(str(tmp_path))
        scan = c.scan_project()
        org = c.assess_organization({"art5_board_oversight": True, "art17_immutable_logs": True})
        report = c.generate_report(scan, org)
        assert report["organizational_assessment"]["completed"] is True
        assert report["organizational_assessment"]["score_pct"] is not None

    def test_report_score_lower_with_critical_gaps(self, tmp_path):
        make_project(tmp_path, {
            "app.py": "import logging\nlogging.FileHandler('app.log')\npassword='abc12345678'"
        })
        c = DORAChecker(str(tmp_path))
        scan = c.scan_project()
        report = c.generate_report(scan)
        assert report["combined_score_pct"] < 100

    def test_report_regulation_metadata(self, tmp_path):
        c = DORAChecker(str(tmp_path))
        report = c.generate_report()
        assert "2022/2554" in report["regulation"]
        assert report["in_force"] == "2025-01-17"

    def test_report_trust_layer_recommended_with_log_gap(self, tmp_path):
        make_project(tmp_path, {"log.py": "import logging\nlogging.FileHandler('events.log')"})
        c = DORAChecker(str(tmp_path))
        scan = c.scan_project()
        report = c.generate_report(scan)
        assert report["trust_layer_recommended"] is True
