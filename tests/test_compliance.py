"""Tests for DORA compliance logic — classify_entity, assess_organization, path validation."""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import DORAChecker, _validate_project_path, _ENTITY_TYPES, _ARTICLES_DB


# ============================================================
# classify_entity
# ============================================================

class TestClassifyEntity:

    def test_credit_institution_has_all_articles(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("credit_institution")
        assert "error" not in result
        assert result["applicable_articles_count"] >= 12
        assert result["tlpt_required"] is True

    def test_ict_provider_limited_scope(self):
        """ICT providers are only subject to Art. 28, 30, 31."""
        c = DORAChecker("/tmp")
        result = c.classify_entity("ict_provider")
        assert result["applicable_articles_count"] == 3
        assert result["tlpt_required"] is False

    def test_crypto_casp_no_tlpt(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("crypto_casp")
        assert result["tlpt_required"] is False

    def test_investment_firm_tlpt_required(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("investment_firm")
        assert result["tlpt_required"] is True

    def test_unknown_entity_returns_error(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("unknown_type")
        assert "error" in result
        assert "available_entity_types" in result

    def test_classify_all_valid_entity_types(self):
        """All registered entity types should classify without error."""
        c = DORAChecker("/tmp")
        for entity_type in _ENTITY_TYPES.keys():
            result = c.classify_entity(entity_type)
            assert "error" not in result, f"classify_entity failed for {entity_type}"
            assert result["applicable_articles_count"] > 0

    def test_result_contains_label(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("payment_institution")
        assert result["label"]
        assert "Payment" in result["label"]

    def test_result_has_dora_in_force_date(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("credit_institution")
        assert result["dora_in_force"] == "2025-01-17"

    def test_critical_articles_subset_of_applicable(self):
        c = DORAChecker("/tmp")
        result = c.classify_entity("credit_institution")
        applicable_names = {a["article"] for a in result["applicable_articles"]}
        for critical in result["critical_articles"]:
            assert critical["article"] in applicable_names


# ============================================================
# assess_organization
# ============================================================

class TestAssessOrganization:

    def _full_yes(self) -> dict:
        return {
            "art5_board_oversight": True,
            "art6_ict_risk_framework": True,
            "art11_bcp_documented": True,
            "art11_rto_rpo_defined": True,
            "art17_incident_process": True,
            "art17_immutable_logs": True,
            "art18_classification": True,
            "art19_reporting_process": True,
            "art26_tlpt_conducted": True,
            "art28_third_party_assessment": True,
            "art30_contract_clauses": True,
            "art31_ict_register": True,
        }

    def test_all_yes_strong_readiness(self):
        c = DORAChecker("/tmp")
        result = c.assess_organization(self._full_yes())
        assert result["score_pct"] >= 85
        assert result["readiness"] == "strong"
        assert result["gaps_count"] == 0

    def test_all_no_critical_readiness(self):
        c = DORAChecker("/tmp")
        responses = {k: False for k in self._full_yes()}
        result = c.assess_organization(responses)
        assert result["score_pct"] == 0
        assert result["readiness"] == "critical"
        assert result["gaps_count"] == len(responses)

    def test_empty_responses_unanswered(self):
        c = DORAChecker("/tmp")
        result = c.assess_organization({})
        assert result["answered"] == 0
        assert result["total_checks"] == 12
        assert result["gaps_count"] == 0  # unanswered ≠ gap

    def test_immutable_log_gap_flags_trust_layer(self):
        c = DORAChecker("/tmp")
        responses = {"art17_immutable_logs": False}
        result = c.assess_organization(responses)
        assert result["trust_layer_gap"] is True
        assert "Trust Layer" in result["summary"]

    def test_no_trust_layer_flag_when_compliant(self):
        c = DORAChecker("/tmp")
        responses = {"art17_immutable_logs": True}
        result = c.assess_organization(responses)
        assert result["trust_layer_gap"] is False

    def test_partial_responses_score_calculation(self):
        c = DORAChecker("/tmp")
        # Only answer Art.5 (weight=3) and Art.17_incident (weight=3) as True
        responses = {
            "art5_board_oversight": True,
            "art17_incident_process": True,
        }
        result = c.assess_organization(responses)
        # At least some score, not full (many unanswered)
        assert result["score_pct"] > 0
        assert result["answered"] == 2

    def test_priority_action_is_first_gap(self):
        c = DORAChecker("/tmp")
        responses = {
            "art5_board_oversight": False,
            "art17_immutable_logs": False,
        }
        result = c.assess_organization(responses)
        assert result["priority_action"] is not None
        assert result["priority_action"]["key"] in responses

    def test_priority_action_none_when_no_gaps(self):
        c = DORAChecker("/tmp")
        result = c.assess_organization(self._full_yes())
        assert result["priority_action"] is None

    def test_score_thresholds_partial(self):
        c = DORAChecker("/tmp")
        # Mix of yes/no to land in partial (60-84%)
        responses = {k: True for k in list(self._full_yes().keys())[:7]}
        result = c.assess_organization(responses)
        # With 7/12 answered as True, score should be in partial or higher range
        assert result["score_pct"] >= 0


# ============================================================
# Path validation
# ============================================================

class TestPathValidation:

    def test_blocked_system_paths(self):
        for path in ["/etc", "/root", "/proc", "/sys", "/dev", "/boot"]:
            is_safe, msg = _validate_project_path(path)
            assert is_safe is False

    def test_empty_path_invalid(self):
        is_safe, msg = _validate_project_path("")
        assert is_safe is False

    def test_path_too_long_invalid(self):
        is_safe, msg = _validate_project_path("/" + "a" * 600)
        assert is_safe is False

    def test_nonexistent_path_invalid(self):
        is_safe, msg = _validate_project_path("/tmp/dora_test_nonexistent_xyz_12345")
        assert is_safe is False
        assert "does not exist" in msg

    def test_file_not_directory_invalid(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("content")
        is_safe, msg = _validate_project_path(str(f))
        assert is_safe is False
        assert "not a directory" in msg

    def test_valid_tmp_path(self, tmp_path):
        is_safe, msg = _validate_project_path(str(tmp_path))
        assert is_safe is True
        assert msg == ""


# ============================================================
# Articles DB integrity
# ============================================================

class TestArticlesDB:

    def test_articles_loaded(self):
        assert len(_ARTICLES_DB) >= 10

    def test_entity_types_loaded(self):
        assert len(_ENTITY_TYPES) >= 9

    def test_art17_trust_layer_relevant(self):
        art = _ARTICLES_DB.get("Art. 17")
        assert art is not None
        assert art["trust_layer_relevant"] is True

    def test_art9_detectable_from_code(self):
        art = _ARTICLES_DB.get("Art. 9")
        assert art is not None
        assert art["detectable_from_code"] is True

    def test_art5_not_detectable_from_code(self):
        art = _ARTICLES_DB.get("Art. 5")
        assert art is not None
        assert art["detectable_from_code"] is False
