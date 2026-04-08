#!/usr/bin/env python3
"""
MCP Server: DORA Compliance Scanner
Scans projects and organisations for DORA (Digital Operational Resilience Act) compliance gaps.

DORA (EU) 2022/2554 — in force since January 17, 2025.
Targets: banks, payment institutions, investment firms, crypto CASPs, insurers, ICT providers.
"""

import ast
import os
import re
import sys
import json
import time
import logging
import contextvars
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FREE_TIER_DAILY_LIMIT = 10
_MCP_PORT = 8091

_PRICING_URL = "https://mcp.arkforge.tech/en/mcp-dora.html?utm_source=pypi"
_TRUST_LAYER_URL = "https://arkforge.tech/trust?utm_source=dora-mcp"

FREE_TIER_BANNER = (
    f"Free tier: {FREE_TIER_DAILY_LIMIT} scans/day — Pro: unlimited scans + CI/CD API "
    f"at 29€/mo → {_PRICING_URL}"
)

TRUST_LAYER_CTA = (
    "DORA Art.17 requires tamper-proof incident records — "
    "Trust Layer seals each log entry at creation: "
    f"arkforge.tech/trust?utm_source=dora-mcp"
)

TRUST_LAYER_CTA_GAPS = (
    "Your system has DORA compliance gaps on incident logging. "
    "Trust Layer makes every incident record tamper-proof and verifiable by supervisors "
    f"without routing through ArkForge → {_TRUST_LAYER_URL}"
)

# ---------------------------------------------------------------------------
# Articles knowledge base
# ---------------------------------------------------------------------------

_ARTICLES_DB_PATH = Path(__file__).parent / "data" / "dora_articles.json"


def _load_articles_db() -> Dict[str, Any]:
    try:
        data = json.loads(_ARTICLES_DB_PATH.read_text())
        return {a["article"]: a for a in data.get("articles", [])}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_entity_types() -> Dict[str, Any]:
    try:
        data = json.loads(_ARTICLES_DB_PATH.read_text())
        return data.get("entity_types", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


_ARTICLES_DB: Dict[str, Any] = _load_articles_db()
_ENTITY_TYPES: Dict[str, Any] = _load_entity_types()

# ---------------------------------------------------------------------------
# Plan context (ContextVar — set by middleware, read by tools)
# ---------------------------------------------------------------------------

_current_plan: contextvars.ContextVar[str] = contextvars.ContextVar("_current_plan", default="free")
_scan_remaining: contextvars.ContextVar[int] = contextvars.ContextVar("_scan_remaining", default=FREE_TIER_DAILY_LIMIT)

# ---------------------------------------------------------------------------
# API Key Manager
# ---------------------------------------------------------------------------

_API_KEYS_PATH = Path(__file__).parent / "data" / "api_keys.json"


class ApiKeyManager:
    def __init__(self, path: Path = _API_KEYS_PATH):
        self._path = path
        self._keys: Dict[str, Dict] = {}
        self._loaded_at: float = 0
        self._reload()

    def _reload(self):
        merged: Dict[str, Dict] = {}
        try:
            data = json.loads(self._path.read_text())
            for entry in data.get("keys", []):
                merged[entry["key"]] = entry
            for api_key, info in data.items():
                if api_key == "keys":
                    continue
                if isinstance(info, dict):
                    info["key"] = api_key
                    merged[api_key] = info
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        self._keys = merged
        self._loaded_at = time.time()

    def verify(self, key: str) -> Optional[Dict]:
        if time.time() - self._loaded_at > 60:
            self._reload()
        info = self._keys.get(key)
        if not info:
            return None
        if not info.get("active", True):
            return None
        return info


_api_key_manager = ApiKeyManager()

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

_RATE_LIMITER_PATH = Path(__file__).parent / "data" / "rate_limits.json"


class RateLimiter:
    _PERSIST_PATH = _RATE_LIMITER_PATH
    _CLEANUP_INTERVAL = 3600

    def __init__(self):
        self._clients: Dict[str, Any] = {}
        self._last_cleanup = time.time()
        self._load()

    def _load(self):
        try:
            self._clients = json.loads(self._PERSIST_PATH.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            self._clients = {}

    def _save(self):
        try:
            self._PERSIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._PERSIST_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._clients))
            tmp.replace(self._PERSIST_PATH)
        except OSError:
            pass

    def _cleanup(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self._clients = {k: v for k, v in self._clients.items() if v.get("date") == today}
        self._last_cleanup = time.time()

    def check(self, ip: str) -> tuple[bool, int]:
        if time.time() - self._last_cleanup > self._CLEANUP_INTERVAL:
            self._cleanup()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = self._clients.get(ip, {})
        if entry.get("date") != today:
            entry = {"date": today, "count": 0}
        if entry["count"] >= FREE_TIER_DAILY_LIMIT:
            return False, 0
        entry["count"] += 1
        self._clients[ip] = entry
        self._save()
        remaining = FREE_TIER_DAILY_LIMIT - entry["count"]
        return True, remaining


_rate_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# Paywall enforcement
# ---------------------------------------------------------------------------

_PLAN_ORDER = {"free": 0, "pro": 1, "certified": 2}

_PLAN_INFO = {
    "pro": {"plan": "Pro", "price": "29€/mo"},
    "certified": {"plan": "Certified", "price": "99€/mo"},
}


def _require_plan(min_plan: str, tool_name: str) -> Optional[dict]:
    current = _current_plan.get()
    if _PLAN_ORDER.get(current, 0) >= _PLAN_ORDER.get(min_plan, 0):
        return None
    info = _PLAN_INFO.get(min_plan, {"plan": min_plan.title(), "price": "—"})
    return {
        "upgrade_required": True,
        "tool": tool_name,
        "required_plan": info["plan"],
        "current_plan": current,
        "message": f"'{tool_name}' requires the {info['plan']} plan ({info['price']}).",
        "how_to_unlock": "Add your API key via the X-Api-Key header or Authorization: Bearer <key>.",
        "upgrade_url": _PRICING_URL,
        "get_key": _PRICING_URL,
    }


def _add_banner(result: dict) -> dict:
    current = _current_plan.get()
    remaining = _scan_remaining.get()

    has_logging_gaps = bool(result.get("findings", {}).get("mutable_logging")) or \
                       bool(result.get("findings", {}).get("no_structured_logging"))

    if current in ("pro", "certified"):
        if has_logging_gaps:
            result["trust_layer"] = TRUST_LAYER_CTA_GAPS
        else:
            result["trust_layer"] = TRUST_LAYER_CTA
        return result

    # Free tier — contextual urgency
    if remaining <= 1:
        upgrade_msg = (
            f"⚠ Last free scan today. Upgrade to Pro for unlimited scans → {_PRICING_URL}"
        )
    elif remaining <= 3:
        upgrade_msg = (
            f"{remaining} free scans remaining today. "
            f"Pro: unlimited → {_PRICING_URL}"
        )
    else:
        upgrade_msg = FREE_TIER_BANNER

    result["upgrade"] = upgrade_msg
    result["upgrade_url"] = _PRICING_URL

    if has_logging_gaps:
        result["trust_layer"] = TRUST_LAYER_CTA_GAPS
    else:
        result["trust_layer"] = TRUST_LAYER_CTA

    if result.get("recommendations") and isinstance(result["recommendations"], list):
        result["recommendations"].append({
            "type": "upgrade",
            "priority": "info",
            "title": "Pro: Unlimited scans + CI/CD integration",
            "description": upgrade_msg,
        })

    return result


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------

_BLOCKED_PATHS = ["/etc", "/proc", "/sys", "/dev", "/root", "/boot"]
_MAX_PATH_LEN = 512


def _validate_project_path(project_path: str) -> tuple[bool, str]:
    if not project_path or len(project_path) > _MAX_PATH_LEN:
        return False, "Invalid project path: empty or too long."
    p = Path(project_path).resolve()
    for blocked in _BLOCKED_PATHS:
        if str(p).startswith(blocked):
            return False, f"Access to '{blocked}' is not allowed."
    if not p.exists():
        return False, f"Path does not exist: {project_path}"
    if not p.is_dir():
        return False, f"Path is not a directory: {project_path}"
    return True, ""


# ---------------------------------------------------------------------------
# DORA Scanner — core detection patterns
# ---------------------------------------------------------------------------

# Third-party SDK imports that indicate ICT dependencies (Art. 28, 31)
_THIRD_PARTY_PATTERNS = {
    "AWS": [r"\bimport boto3\b", r"\bfrom botocore\b", r"\bimport botocore\b"],
    "Azure": [r"\bfrom azure\b", r"\bimport azure\b"],
    "GCP": [r"\bfrom google\.cloud\b", r"\bimport google\.cloud\b"],
    "Stripe": [r"\bimport stripe\b", r"\bfrom stripe\b"],
    "Twilio": [r"\bimport twilio\b", r"\bfrom twilio\b"],
    "SendGrid": [r"\bimport sendgrid\b", r"\bfrom sendgrid\b"],
    "Plaid": [r"\bimport plaid\b", r"\bfrom plaid\b"],
    "Salesforce": [r"\bimport simple_salesforce\b", r"\bfrom simple_salesforce\b"],
    "Datadog": [r"\bimport datadog\b", r"\bfrom datadog\b"],
    "PagerDuty": [r"\bimport pdpyras\b", r"\bimport pypd\b"],
    "Slack": [r"\bimport slack_sdk\b", r"\bfrom slack_sdk\b", r"\bimport slack\b"],
    "OpenAI": [r"\bimport openai\b", r"\bfrom openai\b"],
    "Anthropic": [r"\bimport anthropic\b", r"\bfrom anthropic\b"],
    "requests (HTTP)": [r"\bimport requests\b"],
    "httpx (HTTP)": [r"\bimport httpx\b", r"\bfrom httpx\b"],
    "aiohttp (HTTP)": [r"\bimport aiohttp\b", r"\bfrom aiohttp\b"],
    "Celery": [r"\bfrom celery\b", r"\bimport celery\b"],
    "Redis": [r"\bimport redis\b", r"\bfrom redis\b"],
    "Kafka": [r"\bfrom kafka\b", r"\bimport kafka\b"],
}

# Mutable logging patterns (Art. 10, 17)
_MUTABLE_LOG_PATTERNS = [
    r"logging\.basicConfig\s*\(.*filename\s*=",
    r"FileHandler\s*\(",
    r"RotatingFileHandler\s*\(",
    r"TimedRotatingFileHandler\s*\(",
    r"open\s*\([^)]+['\"]a['\"]",   # open(..., 'a') append mode
    r"open\s*\([^)]+['\"]w['\"]",   # open(..., 'w') write mode
]

# Structured logging patterns (positive — good)
_STRUCTURED_LOG_PATTERNS = [
    r"\bimport structlog\b",
    r"\bfrom structlog\b",
    r"\bimport loguru\b",
    r"\bfrom loguru\b",
    r"\bimport python_json_logger\b",
    r"JsonFormatter",
]

# Retry / resilience patterns (Art. 11)
_RETRY_PATTERNS = [
    r"\bfrom tenacity\b", r"\bimport tenacity\b",
    r"\bfrom backoff\b", r"\bimport backoff\b",
    r"\bretry\s*\(", r"@retry",
    r"\bmax_retries\b", r"\bretry_count\b",
]

_CIRCUIT_BREAKER_PATTERNS = [
    r"\bimport pybreaker\b", r"\bfrom pybreaker\b",
    r"CircuitBreaker", r"circuit_breaker",
    r"\bimport circuitbreaker\b",
]

# Hardcoded credential patterns (Art. 9)
_HARDCODED_CRED_PATTERNS = [
    r"(?i)(password|passwd|secret|api_key|apikey|token|access_key|private_key)\s*=\s*['\"][a-zA-Z0-9+/=_\-]{8,}['\"]",
    r"(?i)(sk-|ak-|pk-|rk-)[a-zA-Z0-9]{20,}",
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"AKIA[0-9A-Z]{16}",  # AWS access key
]

# Security testing patterns (Art. 24, 25)
_SECURITY_TEST_PATTERNS = [
    r"\bbandit\b", r"\bsafety\b", r"\bsemgrep\b",
    r"\bpytest-security\b", r"\bsnyk\b",
    r"security.*test", r"test.*security",
    r"\bpenetration\b", r"\bpentest\b",
]

_SAST_CONFIG_FILES = [
    ".bandit", "bandit.yaml", "bandit.yml",
    ".semgrep", "semgrep.yml",
    "safety.cfg", ".snyk",
    "sonar-project.properties",
]

# Secrets management (positive — good)
_SECRETS_MGMT_PATTERNS = [
    r"\bimport vault\b", r"\bfrom vault\b",
    r"os\.environ\.get\s*\(",
    r"os\.getenv\s*\(",
    r"dotenv", r"python-dotenv",
    r"SecretManager", r"KeyVault",
    r"AWS_SECRET", r"SSM",
]


class DORAChecker:
    """Core DORA compliance scanner engine."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self._scan_cache: Optional[Dict] = None

    def _iter_source_files(self):
        """Yield Python source files in the project."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", "dist", "build", ".egg-info"}
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname.endswith((".py", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".env.example")):
                    yield Path(root) / fname

    def _read_file_safe(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _match_patterns(self, content: str, patterns: List[str]) -> List[str]:
        matched = []
        for pattern in patterns:
            if re.search(pattern, content):
                matched.append(pattern)
        return matched

    def scan_project(self) -> Dict[str, Any]:
        """
        Scan the project for DORA-relevant ICT compliance signals.

        Detects:
        - ICT third-party dependencies (Art. 28, 31)
        - Mutable / unstructured logging (Art. 10, 17)
        - Missing retry / circuit breaker patterns (Art. 11)
        - Hardcoded credentials (Art. 9)
        - Missing security testing tooling (Art. 24, 25)
        """
        files_scanned = 0
        third_party_deps: Dict[str, List[str]] = {}
        mutable_logging_files: List[str] = []
        has_structured_logging = False
        has_retry = False
        has_circuit_breaker = False
        hardcoded_creds_files: List[str] = []
        has_security_tests = False
        has_sast_config = False
        has_secrets_mgmt = False
        all_content_lines: List[str] = []

        for fpath in self._iter_source_files():
            content = self._read_file_safe(fpath)
            if not content:
                continue
            files_scanned += 1
            rel_path = str(fpath.relative_to(self.project_path))

            # ICT third-party dependencies
            for vendor, patterns in _THIRD_PARTY_PATTERNS.items():
                if any(re.search(p, content) for p in patterns):
                    if vendor not in third_party_deps:
                        third_party_deps[vendor] = []
                    third_party_deps[vendor].append(rel_path)

            # Mutable logging
            if any(re.search(p, content) for p in _MUTABLE_LOG_PATTERNS):
                mutable_logging_files.append(rel_path)

            # Structured logging (positive)
            if any(re.search(p, content) for p in _STRUCTURED_LOG_PATTERNS):
                has_structured_logging = True

            # Retry/resilience
            if any(re.search(p, content) for p in _RETRY_PATTERNS):
                has_retry = True

            # Circuit breaker
            if any(re.search(p, content) for p in _CIRCUIT_BREAKER_PATTERNS):
                has_circuit_breaker = True

            # Hardcoded credentials
            for pattern in _HARDCODED_CRED_PATTERNS:
                if re.search(pattern, content):
                    hardcoded_creds_files.append(rel_path)
                    break

            # Security tests
            if any(re.search(p, content, re.IGNORECASE) for p in _SECURITY_TEST_PATTERNS):
                has_security_tests = True

            # SAST config files
            if fpath.name in _SAST_CONFIG_FILES:
                has_sast_config = True

            # Secrets management
            if any(re.search(p, content) for p in _SECRETS_MGMT_PATTERNS):
                has_secrets_mgmt = True

        # Check root for SAST config files
        for fname in _SAST_CONFIG_FILES:
            if (self.project_path / fname).exists():
                has_sast_config = True

        has_http_clients = any(
            v for v in ["requests (HTTP)", "httpx (HTTP)", "aiohttp (HTTP)"]
            if v in third_party_deps
        )

        findings = {
            "third_party_dependencies": third_party_deps,
            "mutable_logging": mutable_logging_files,
            "has_structured_logging": has_structured_logging,
            "has_retry": has_retry,
            "has_circuit_breaker": has_circuit_breaker,
            "hardcoded_credentials": hardcoded_creds_files,
            "has_security_tests": has_security_tests,
            "has_sast_config": has_sast_config,
            "has_secrets_management": has_secrets_mgmt,
            "has_external_http_calls": has_http_clients,
        }

        gaps = self._compute_gaps(findings)
        self._scan_cache = {"findings": findings, "gaps": gaps, "files_scanned": files_scanned}
        return self._scan_cache

    def _compute_gaps(self, findings: Dict) -> List[Dict]:
        gaps = []

        if findings["mutable_logging"]:
            gaps.append({
                "gap": "mutable_logging",
                "article": "Art. 10 + Art. 17",
                "severity": "critical",
                "description": "Log files are mutable — incident records can be altered or deleted. DORA requires tamper-proof audit trails.",
                "files": findings["mutable_logging"][:5],
                "fix": "Replace file-based logging with an immutable log store. Use Trust Layer to seal incident records at creation.",
                "trust_layer_relevant": True,
            })
        elif not findings["has_structured_logging"]:
            gaps.append({
                "gap": "no_structured_logging",
                "article": "Art. 10",
                "severity": "high",
                "description": "No structured logging library detected (structlog, loguru). Unstructured logs are harder to query and audit.",
                "fix": "Adopt structlog or loguru for machine-readable, queryable incident logs.",
                "trust_layer_relevant": True,
            })

        if not findings["has_retry"] and findings["has_external_http_calls"]:
            gaps.append({
                "gap": "missing_retry",
                "article": "Art. 11",
                "severity": "high",
                "description": "External HTTP calls detected without retry logic. DORA requires recovery mechanisms for ICT failures.",
                "fix": "Add retry logic using tenacity or backoff on all external API calls.",
                "trust_layer_relevant": False,
            })

        if not findings["has_circuit_breaker"] and findings["has_external_http_calls"]:
            gaps.append({
                "gap": "missing_circuit_breaker",
                "article": "Art. 11",
                "severity": "medium",
                "description": "No circuit breaker pattern detected. Circuit breakers prevent cascading failures when ICT third-party services are unavailable.",
                "fix": "Implement circuit breakers using pybreaker or a similar library.",
                "trust_layer_relevant": False,
            })

        if findings["hardcoded_credentials"]:
            gaps.append({
                "gap": "hardcoded_credentials",
                "article": "Art. 9",
                "severity": "critical",
                "description": "Hardcoded credentials found in source code. This violates ICT security requirements.",
                "files": findings["hardcoded_credentials"][:5],
                "fix": "Move all secrets to environment variables or a secrets vault (HashiCorp Vault, AWS Secrets Manager).",
                "trust_layer_relevant": False,
            })
        elif not findings["has_secrets_management"]:
            gaps.append({
                "gap": "no_secrets_management",
                "article": "Art. 9",
                "severity": "medium",
                "description": "No secrets management pattern detected. Credentials may be hardcoded or improperly stored.",
                "fix": "Use os.environ, python-dotenv for local dev and a vault solution for production.",
                "trust_layer_relevant": False,
            })

        if not findings["has_security_tests"] and not findings["has_sast_config"]:
            gaps.append({
                "gap": "no_security_tests",
                "article": "Art. 24 + Art. 25",
                "severity": "high",
                "description": "No security testing tooling detected (bandit, semgrep, safety, snyk). DORA requires annual vulnerability assessments and source code reviews.",
                "fix": "Add bandit or semgrep to your CI pipeline. Run safety check on dependencies.",
                "trust_layer_relevant": False,
            })

        if findings["third_party_dependencies"]:
            vendor_count = len(findings["third_party_dependencies"])
            gaps.append({
                "gap": "ict_register_needed",
                "article": "Art. 31",
                "severity": "high",
                "description": f"{vendor_count} ICT third-party dependency(ies) detected. DORA Art.31 requires a register of all ICT third-party service providers.",
                "vendors_detected": list(findings["third_party_dependencies"].keys()),
                "fix": "Maintain a register of all ICT third-party providers. Use generate_ict_register tool to scaffold Art.31 register.",
                "trust_layer_relevant": False,
            })

        return gaps

    def classify_entity(self, entity_type: str) -> Dict[str, Any]:
        """Classify a DORA entity type and return applicable articles and obligations."""
        info = _ENTITY_TYPES.get(entity_type)
        if not info:
            available = list(_ENTITY_TYPES.keys())
            return {
                "error": f"Unknown entity type: '{entity_type}'",
                "available_entity_types": available,
            }

        key_articles = info.get("key_articles", [])
        articles_detail = []
        for art_key in key_articles:
            art = _ARTICLES_DB.get(art_key)
            if art:
                articles_detail.append({
                    "article": art_key,
                    "title": art["title"],
                    "severity": art.get("severity", "medium"),
                    "detectable_from_code": art.get("detectable_from_code", False),
                    "trust_layer_relevant": art.get("trust_layer_relevant", False),
                })

        critical_articles = [a for a in articles_detail if a["severity"] == "critical"]

        return {
            "entity_type": entity_type,
            "label": info["label"],
            "examples": info.get("examples", []),
            "tlpt_required": info.get("tlpt_required", False),
            "applicable_articles_count": len(key_articles),
            "applicable_articles": articles_detail,
            "critical_articles": critical_articles,
            "dora_in_force": "2025-01-17",
            "summary": (
                f"As a {info['label']}, you are subject to {len(key_articles)} DORA articles. "
                f"{len(critical_articles)} are critical priority. "
                + ("TLPT (Threat-Led Penetration Testing) is required every 3 years. " if info.get("tlpt_required") else "")
            ),
        }

    def assess_organization(self, responses: Dict[str, bool]) -> Dict[str, Any]:
        """
        Score DORA organizational readiness from YES/NO questionnaire responses.

        Expected keys in responses (all boolean):
          art5_board_oversight         — Board has approved ICT risk strategy
          art6_ict_risk_framework      — ICT risk management framework documented
          art11_bcp_documented         — Business continuity plan documented
          art11_rto_rpo_defined        — RTO and RPO are defined and tested
          art17_incident_process       — Incident management process documented
          art17_immutable_logs         — Incident logs are tamper-proof / immutable
          art18_classification         — Incident classification framework exists
          art19_reporting_process      — Regulatory reporting process (4h/72h/1mo) defined
          art26_tlpt_conducted         — TLPT conducted in last 3 years (if applicable)
          art28_third_party_assessment — Pre-contractual ICT risk assessments performed
          art30_contract_clauses       — ICT contracts include required DORA provisions
          art31_ict_register           — ICT third-party register maintained and updated
        """
        checklist = {
            "art5_board_oversight":         {"article": "Art. 5",  "label": "Board-approved ICT risk strategy",           "weight": 3, "severity": "critical"},
            "art6_ict_risk_framework":      {"article": "Art. 6",  "label": "ICT risk management framework documented",   "weight": 3, "severity": "critical"},
            "art11_bcp_documented":         {"article": "Art. 11", "label": "Business continuity plan documented",         "weight": 2, "severity": "high"},
            "art11_rto_rpo_defined":        {"article": "Art. 11", "label": "RTO and RPO defined and tested",              "weight": 2, "severity": "high"},
            "art17_incident_process":       {"article": "Art. 17", "label": "Incident management process documented",      "weight": 3, "severity": "critical"},
            "art17_immutable_logs":         {"article": "Art. 17", "label": "Incident logs are tamper-proof / immutable",  "weight": 3, "severity": "critical"},
            "art18_classification":         {"article": "Art. 18", "label": "Incident classification framework exists",    "weight": 2, "severity": "critical"},
            "art19_reporting_process":      {"article": "Art. 19", "label": "Regulatory reporting process defined (4h/72h/1mo)", "weight": 3, "severity": "critical"},
            "art26_tlpt_conducted":         {"article": "Art. 26", "label": "TLPT conducted in last 3 years",              "weight": 1, "severity": "medium"},
            "art28_third_party_assessment": {"article": "Art. 28", "label": "Pre-contractual ICT risk assessments done",   "weight": 2, "severity": "high"},
            "art30_contract_clauses":       {"article": "Art. 30", "label": "DORA contract provisions in ICT agreements",  "weight": 2, "severity": "high"},
            "art31_ict_register":           {"article": "Art. 31", "label": "ICT third-party register maintained",         "weight": 2, "severity": "high"},
        }

        total_weight = 0
        achieved_weight = 0
        results = []
        gaps = []

        for key, meta in checklist.items():
            w = meta["weight"]
            total_weight += w
            answered = responses.get(key)
            if answered is True:
                achieved_weight += w
                results.append({**meta, "key": key, "status": "compliant", "response": True})
            elif answered is False:
                results.append({**meta, "key": key, "status": "gap", "response": False})
                gaps.append({
                    "key": key,
                    "article": meta["article"],
                    "label": meta["label"],
                    "severity": meta["severity"],
                })
            else:
                results.append({**meta, "key": key, "status": "not_answered", "response": None})

        score_pct = round(100 * achieved_weight / total_weight) if total_weight else 0
        answered_count = sum(1 for k in checklist if responses.get(k) is not None)

        if score_pct >= 85:
            readiness = "strong"
        elif score_pct >= 60:
            readiness = "partial"
        elif score_pct >= 30:
            readiness = "insufficient"
        else:
            readiness = "critical"

        has_immutable_log_gap = responses.get("art17_immutable_logs") is False

        return {
            "score_pct": score_pct,
            "readiness": readiness,
            "answered": answered_count,
            "total_checks": len(checklist),
            "gaps_count": len(gaps),
            "results": results,
            "gaps": gaps,
            "priority_action": gaps[0] if gaps else None,
            "trust_layer_gap": has_immutable_log_gap,
            "summary": (
                f"DORA organizational readiness: {score_pct}% ({readiness.upper()}). "
                f"{len(gaps)} gap(s) identified across {answered_count}/{len(checklist)} checks. "
                + ("⚠ Immutable incident logging gap — Trust Layer recommended. " if has_immutable_log_gap else "")
            ),
        }

    def generate_ict_register(self, scan_results: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate an Art. 31 ICT third-party register skeleton from scan results.
        [Pro tool]
        """
        if scan_results is None:
            scan_results = self._scan_cache or self.scan_project()

        findings = scan_results.get("findings", {})
        detected = findings.get("third_party_dependencies", {})

        entries = []
        for vendor, files in detected.items():
            criticality = "critical" if vendor in {
                "AWS", "Azure", "GCP", "Stripe", "Plaid", "Kafka"
            } else "important" if vendor in {
                "Redis", "Celery", "OpenAI", "Anthropic"
            } else "non-critical"

            entries.append({
                "provider_name": vendor,
                "service_type": _VENDOR_SERVICE_TYPES.get(vendor, "ICT Service"),
                "classification": criticality,
                "detected_in_files": files[:3],
                "sla_defined": None,
                "audit_rights_in_contract": None,
                "data_location_eu": None,
                "exit_strategy_documented": None,
                "last_risk_assessment": None,
                "contract_expiry": None,
                "notes": "— auto-detected from source code scan —",
            })

        return {
            "article": "Art. 31 — ICT Third-Party Service Provider Register",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project_path": str(self.project_path),
            "providers_detected": len(entries),
            "register": entries,
            "instructions": (
                "Complete the NULL fields for each provider. "
                "Classify providers supporting critical or important functions separately. "
                "Update this register at least annually (Art. 31.2). "
                "Submit to competent authority on request."
            ),
            "register_fields_required": [
                "provider_name", "service_type", "classification",
                "sla_defined", "audit_rights_in_contract",
                "data_location_eu", "exit_strategy_documented",
                "last_risk_assessment", "contract_expiry"
            ],
        }

    def generate_incident_template(self) -> Dict[str, Any]:
        """
        Generate an Art. 17-18 incident management template.
        [Pro tool]
        """
        return {
            "article": "Art. 17-18 — ICT-Related Incident Management",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "classification_framework": {
                "major": {
                    "label": "Major ICT Incident",
                    "criteria": [
                        "Significant number of clients affected",
                        "Significant financial loss (absolute or relative)",
                        "Service disruption > 4 hours for critical services",
                        "Reputational impact (media coverage)",
                        "Data loss / data integrity compromise",
                        "Geographic spread across EU member states"
                    ],
                    "reporting_deadlines": {
                        "initial_notification": "Within 4 hours of classification as major",
                        "intermediate_report": "Within 72 hours of initial notification",
                        "final_report": "Within 1 month of incident resolution"
                    },
                    "regulatory_notification": "Required — notify competent authority and, where applicable, payment service users"
                },
                "significant": {
                    "label": "Significant ICT Incident",
                    "criteria": [
                        "Internal impact only",
                        "Limited client impact",
                        "Service disruption < 4 hours"
                    ],
                    "reporting_deadlines": None,
                    "regulatory_notification": "Internal reporting only"
                },
                "minor": {
                    "label": "Minor ICT Incident",
                    "criteria": ["Negligible client impact", "Resolved within SLA"],
                    "reporting_deadlines": None,
                    "regulatory_notification": "None required"
                }
            },
            "incident_record_template": {
                "incident_id": "INC-YYYY-NNNN",
                "detected_at": "ISO 8601 timestamp",
                "reported_by": "Team / system name",
                "classification": "major | significant | minor",
                "affected_services": [],
                "clients_affected_count": None,
                "financial_impact_eur": None,
                "description": "",
                "root_cause": "",
                "containment_actions": [],
                "resolution_actions": [],
                "resolved_at": None,
                "regulatory_notified_at": None,
                "regulatory_body": "",
                "post_incident_review_date": None,
                "lessons_learned": []
            },
            "immutability_note": (
                "DORA Art. 17 requires incident records to be retained for supervisory inspection. "
                "Records must be tamper-proof — a mutable log file does NOT satisfy this requirement. "
                "Recommended: seal each incident record with Trust Layer (Ed25519 + RFC 3161 timestamp) "
                "to produce a cryptographic proof verifiable by regulators without routing through ArkForge. "
                f"→ {_TRUST_LAYER_URL}"
            ),
            "retention_period": "Minimum 5 years (aligned with GDPR and financial record-keeping obligations)",
        }

    def generate_report(
        self,
        scan_results: Optional[Dict] = None,
        org_assessment: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Generate a full DORA compliance report combining scan + organizational assessment."""
        if scan_results is None:
            scan_results = self._scan_cache or self.scan_project()

        gaps = scan_results.get("gaps", [])
        critical_gaps = [g for g in gaps if g.get("severity") == "critical"]
        high_gaps = [g for g in gaps if g.get("severity") == "high"]

        code_score = max(0, 100 - len(critical_gaps) * 25 - len(high_gaps) * 10)

        org_score = org_assessment.get("score_pct") if org_assessment else None

        if org_score is not None:
            combined_score = round(0.4 * code_score + 0.6 * org_score)
        else:
            combined_score = code_score

        if combined_score >= 85:
            readiness = "strong"
        elif combined_score >= 60:
            readiness = "partial"
        elif combined_score >= 30:
            readiness = "insufficient"
        else:
            readiness = "critical"

        recommendations = []
        for gap in gaps:
            recommendations.append({
                "priority": gap.get("severity", "medium"),
                "article": gap.get("article", ""),
                "gap": gap.get("gap", ""),
                "description": gap.get("description", ""),
                "fix": gap.get("fix", ""),
                "trust_layer_relevant": gap.get("trust_layer_relevant", False),
            })

        has_logging_gap = any(
            g.get("trust_layer_relevant") for g in gaps
        )

        return {
            "report_type": "DORA Compliance Report",
            "regulation": "Digital Operational Resilience Act (EU) 2022/2554",
            "in_force": "2025-01-17",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project_path": str(self.project_path),
            "combined_score_pct": combined_score,
            "readiness": readiness,
            "code_analysis": {
                "files_scanned": scan_results.get("files_scanned", 0),
                "gaps_count": len(gaps),
                "critical_gaps": len(critical_gaps),
                "high_gaps": len(high_gaps),
                "third_party_deps": len(scan_results.get("findings", {}).get("third_party_dependencies", {})),
            },
            "organizational_assessment": {
                "score_pct": org_score,
                "gaps_count": org_assessment.get("gaps_count") if org_assessment else None,
                "completed": org_assessment is not None,
            },
            "recommendations": recommendations,
            "next_steps": [
                "1. Fix critical gaps (mutable logging, hardcoded credentials) — immediate priority.",
                "2. Complete organizational assessment using assess_organization tool.",
                "3. Generate ICT register with generate_ict_register (Pro) — required for Art. 31.",
                "4. Generate incident template with generate_incident_template (Pro) — required for Art. 17-18.",
                "5. Certify this report with Trust Layer for supervisor-ready proof.",
            ] if gaps else [
                "No critical code-level gaps detected.",
                "Complete organizational assessment using assess_organization tool.",
                "Certify this report with Trust Layer for supervisor-ready proof.",
            ],
            "trust_layer_recommended": has_logging_gap,
        }


# Vendor service type mapping for ICT register
_VENDOR_SERVICE_TYPES: Dict[str, str] = {
    "AWS": "Cloud Infrastructure (IaaS/PaaS)",
    "Azure": "Cloud Infrastructure (IaaS/PaaS)",
    "GCP": "Cloud Infrastructure (IaaS/PaaS)",
    "Stripe": "Payment Processing",
    "Twilio": "Communications Platform",
    "SendGrid": "Email Delivery Service",
    "Plaid": "Financial Data Aggregation",
    "Salesforce": "CRM / Business Application",
    "Datadog": "Monitoring & Observability",
    "PagerDuty": "Incident Management Platform",
    "Slack": "Business Communication",
    "OpenAI": "AI / Machine Learning Platform",
    "Anthropic": "AI / Machine Learning Platform",
    "requests (HTTP)": "HTTP Client Library",
    "httpx (HTTP)": "HTTP Client Library",
    "aiohttp (HTTP)": "Async HTTP Client Library",
    "Celery": "Task Queue / Distributed Computing",
    "Redis": "In-Memory Data Store",
    "Kafka": "Event Streaming Platform",
}


# ---------------------------------------------------------------------------
# Trust Layer certification
# ---------------------------------------------------------------------------

def _certify_with_trust_layer(report_data: dict, trust_layer_key: str) -> dict:
    """Submit report to ArkForge Trust Layer for tamper-proof certification."""
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "content": json.dumps(report_data, sort_keys=True),
        "metadata": {
            "type": "dora_compliance_report",
            "regulation": "DORA (EU) 2022/2554",
            "generated_at": report_data.get("generated_at", ""),
            "scanner_version": __version__,
        }
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://trust.arkforge.tech/v1/proxy",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Api-Key": trust_layer_key,
            },
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode("utf-8"))
        return {
            "certified": True,
            "proof_id": result.get("proof_id"),
            "proof_url": result.get("proof_url"),
            "timestamp": result.get("timestamp"),
            "ed25519_signature": result.get("signature"),
            "rfc3161_timestamp": result.get("rfc3161_timestamp"),
            "rekor_log_index": result.get("rekor_log_index"),
            "verification_note": "Verifiable by any third party without routing through ArkForge.",
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"certified": False, "error": f"Trust Layer API error {e.code}: {body[:200]}"}
    except Exception as exc:
        return {"certified": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Rate-limit middleware (ASGI)
# ---------------------------------------------------------------------------

import io


class RateLimitMiddleware:
    """ASGI middleware: rate limiting + API key plan injection."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        # Management endpoints
        if path == "/health" and method == "GET":
            await self._health(scope, receive, send)
            return

        # Only rate-limit tool calls (JSON-RPC POST)
        if method != "POST":
            await self.app(scope, receive, send)
            return

        # Extract API key
        api_key = self._extract_key(scope)
        ip = self._extract_ip(scope)

        if api_key:
            key_info = _api_key_manager.verify(api_key)
            if key_info:
                plan = key_info.get("plan", "pro")
                _current_plan.set(plan)
                _scan_remaining.set(999)
                await self.app(scope, receive, send)
                return

        # Free tier — rate limit
        allowed, remaining = _rate_limiter.check(ip)
        if not allowed:
            await self._rate_limit_response(send)
            return

        _current_plan.set("free")
        _scan_remaining.set(remaining)
        await self.app(scope, receive, send)

    def _extract_key(self, scope) -> Optional[str]:
        headers = dict(scope.get("headers", []))
        key = headers.get(b"x-api-key", b"").decode("utf-8", errors="ignore").strip()
        if key:
            return key
        auth = headers.get(b"authorization", b"").decode("utf-8", errors="ignore").strip()
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    def _extract_ip(self, scope) -> str:
        headers = dict(scope.get("headers", []))
        for h in (b"x-real-ip", b"x-forwarded-for"):
            val = headers.get(h, b"").decode("utf-8", errors="ignore").strip()
            if val:
                return val.split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    async def _health(self, scope, receive, send):
        body = json.dumps({
            "status": "ok",
            "service": "mcp-dora",
            "version": __version__,
            "regulation": "DORA (EU) 2022/2554",
        }).encode("utf-8")
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    async def _rate_limit_response(self, send):
        body = json.dumps({
            "error": {
                "code": 429,
                "message": (
                    f"Free tier limit reached ({FREE_TIER_DAILY_LIMIT} scans/day). "
                    f"Upgrade to Pro for unlimited scans → {_PRICING_URL}"
                ),
            }
        }).encode("utf-8")
        await send({"type": "http.response.start", "status": 429,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

def create_server():
    """Create and return the DORA Compliance Scanner MCP server."""
    mcp = FastMCP(
        name="ArkForge DORA Compliance Scanner",
        instructions=(
            "DORA compliance scanner for financial entities. Scans projects for ICT resilience gaps "
            "and generates Art.31 registers, Art.17-18 incident templates. "
            "Covers: banks, payment institutions, investment firms, crypto CASPs, insurers, ICT providers. "
            f"Free: {FREE_TIER_DAILY_LIMIT} scans/day. Pro: unlimited + CI/CD API at 29€/mo → {_PRICING_URL} "
            f"| Certify reports with Trust Layer → {_TRUST_LAYER_URL}"
        ),
        host="127.0.0.1",
        port=_MCP_PORT,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[
                "mcp.arkforge.tech", "arkforge.tech",
                f"127.0.0.1:{_MCP_PORT}", f"localhost:{_MCP_PORT}",
            ],
        ),
    )

    @mcp.tool()
    def scan_project(project_path: str) -> dict:
        """Scan a project for DORA (Digital Operational Resilience Act) compliance gaps.

        Detects ICT third-party dependencies (Art.28/31), mutable logging (Art.10/17),
        missing retry/circuit-breaker (Art.11), hardcoded credentials (Art.9),
        and missing security testing (Art.24/25).

        Args:
            project_path: Absolute path to the project directory to scan.
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = DORAChecker(project_path)
        result = checker.scan_project()
        return _add_banner(result)

    @mcp.tool()
    def classify_entity(entity_type: str) -> dict:
        """Classify a DORA entity type and return all applicable articles and obligations.

        Args:
            entity_type: One of: credit_institution, payment_institution, e_money_institution,
                         investment_firm, crypto_casp, insurance_undertaking, ict_provider,
                         trading_venue, central_counterparty.
        """
        checker = DORAChecker("/tmp")  # no path needed for classification
        result = checker.classify_entity(entity_type)
        return _add_banner(result)

    @mcp.tool()
    def assess_organization(responses: dict) -> dict:
        """Score DORA organizational readiness from YES/NO questionnaire responses.

        Pass a dict with boolean values for each check. Missing keys are treated as unanswered.

        Expected keys:
          art5_board_oversight, art6_ict_risk_framework, art11_bcp_documented,
          art11_rto_rpo_defined, art17_incident_process, art17_immutable_logs,
          art18_classification, art19_reporting_process, art26_tlpt_conducted,
          art28_third_party_assessment, art30_contract_clauses, art31_ict_register

        Args:
            responses: Dict mapping check keys to True (compliant), False (gap), or omit (not answered).
        """
        checker = DORAChecker("/tmp")
        result = checker.assess_organization(responses)
        return _add_banner(result)

    @mcp.tool()
    def generate_ict_register(project_path: str) -> dict:
        """Generate an Art.31 ICT third-party service provider register skeleton from a project scan.

        Automatically detects vendors from source code and scaffolds the DORA-required register
        with all mandatory fields (classification, SLA, audit rights, data location, exit strategy).

        Args:
            project_path: Absolute path to the project directory to scan.
        """
        gate = _require_plan("pro", "generate_ict_register")
        if gate:
            return gate
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = DORAChecker(project_path)
        checker.scan_project()
        result = checker.generate_ict_register()
        return _add_banner(result)

    @mcp.tool()
    def generate_incident_template(project_path: str = "/tmp") -> dict:
        """Generate an Art.17-18 ICT incident management template with classification framework.

        Includes: incident classification criteria (major/significant/minor), regulatory
        reporting deadlines (4h/72h/1 month), incident record fields, and immutability guidance.

        Args:
            project_path: Optional project path for context (default: current directory).
        """
        gate = _require_plan("pro", "generate_incident_template")
        if gate:
            return gate
        checker = DORAChecker(project_path if project_path != "/tmp" else "/tmp")
        result = checker.generate_incident_template()
        return _add_banner(result)

    @mcp.tool()
    def generate_report(project_path: str, org_responses: dict = {}) -> dict:  # noqa: B006
        """Generate a full DORA compliance report combining code scan and organizational assessment.

        Args:
            project_path: Absolute path to the project directory to scan.
            org_responses: Optional organizational assessment responses (same format as assess_organization).
                           If provided, combined score includes both code and organizational readiness.
        """
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = DORAChecker(project_path)
        scan = checker.scan_project()
        org_result = checker.assess_organization(org_responses) if org_responses else None
        result = checker.generate_report(scan, org_result)
        return _add_banner(result)

    @mcp.tool()
    def certify_report(project_path: str, trust_layer_key: str) -> dict:
        """Certify a DORA compliance report with ArkForge Trust Layer.

        Generates a tamper-proof cryptographic proof (Ed25519 + RFC 3161 timestamp +
        Sigstore/Rekor anchoring) of the compliance report. Verifiable by regulators
        without routing through ArkForge.

        Args:
            project_path: Absolute path to the project to scan and certify.
            trust_layer_key: Your ArkForge Trust Layer API key (X-Api-Key).
        """
        gate = _require_plan("certified", "certify_report")
        if gate:
            return gate
        is_safe, error_msg = _validate_project_path(project_path)
        if not is_safe:
            return {"error": error_msg}
        checker = DORAChecker(project_path)
        scan = checker.scan_project()
        report = checker.generate_report(scan)
        certification = _certify_with_trust_layer(report, trust_layer_key)
        result = {**report, "certification": certification}
        return _add_banner(result)

    return mcp


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    server = create_server()
    if "--http" in sys.argv:
        import uvicorn
        app = RateLimitMiddleware(server.streamable_http_app())
        config = uvicorn.Config(
            app,
            host=server.settings.host,
            port=server.settings.port,
            log_level="info",
        )
        uvicorn.Server(config).run()
    else:
        server.run(transport="stdio")
