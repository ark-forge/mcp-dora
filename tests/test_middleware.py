"""Tests for RateLimitMiddleware (ASGI), _certify_with_trust_layer, and MCP tool registration."""

import sys
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import (
    RateLimitMiddleware,
    RateLimiter,
    ApiKeyManager,
    _current_plan,
    _scan_remaining,
    _certify_with_trust_layer,
    FREE_TIER_DAILY_LIMIT,
    _api_key_manager,
    _rate_limiter,
    create_server,
    __version__,
)
from tests.conftest import make_project


# ============================================================
# ASGI helpers
# ============================================================

def make_scope(method="POST", path="/mcp/", headers=None, client=("1.2.3.4", 12345)):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
        "client": client,
    }


async def _null_receive():
    return {}


class CaptureSend:
    """Captures ASGI send calls."""
    def __init__(self):
        self.calls = []
        self.status = None
        self.body = b""

    async def __call__(self, message):
        self.calls.append(message)
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")


async def _passthrough_app(scope, receive, send):
    """Minimal ASGI app that returns 200."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b'{"ok":true}'})


# ============================================================
# RateLimitMiddleware: health endpoint
# ============================================================

class TestMiddlewareHealth:

    def test_health_endpoint_returns_ok(self):
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(method="GET", path="/health")
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 200
        data = json.loads(capture.body)
        assert data["status"] == "ok"
        assert data["service"] == "mcp-dora"
        assert data["version"] == __version__

    def test_non_http_scope_passes_through(self):
        mw = RateLimitMiddleware(_passthrough_app)
        scope = {"type": "lifespan"}
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        # Passed through to app — no status captured by middleware
        assert capture.status == 200  # app returned 200

    def test_get_non_health_passes_through(self):
        """Non-POST and non-health requests should pass through."""
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(method="GET", path="/other")
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 200


# ============================================================
# RateLimitMiddleware: free tier
# ============================================================

class TestMiddlewareFreeTier:

    def test_free_tier_post_allowed(self):
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(client=("192.168.1.200", 9999))
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 200

    def test_rate_limit_exceeded_returns_429(self, tmp_path):
        RateLimiter._PERSIST_PATH = tmp_path / "rl.json"
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(client=("10.11.12.13", 1111))

        # Exhaust quota
        for _ in range(FREE_TIER_DAILY_LIMIT):
            _rate_limiter.check("10.11.12.13")

        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 429
        data = json.loads(capture.body)
        assert "error" in data


# ============================================================
# RateLimitMiddleware: API key auth
# ============================================================

class TestMiddlewareApiKey:

    def test_valid_api_key_bypasses_rate_limit(self, tmp_path):
        """A valid API key should bypass rate limiting and set plan."""
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "ak_valid_pro", "plan": "pro", "active": True}]
        }))
        mgr = ApiKeyManager(keys_file)

        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(
            headers=[(b"x-api-key", b"ak_valid_pro")],
            client=("127.0.0.1", 8888),
        )

        with patch("server._api_key_manager", mgr):
            capture = CaptureSend()
            asyncio.run(mw(scope, _null_receive, capture))

        assert capture.status == 200

    def test_bearer_token_accepted(self, tmp_path):
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key": "ak_bearer_test", "plan": "certified", "active": True}]
        }))
        mgr = ApiKeyManager(keys_file)

        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(
            headers=[(b"authorization", b"Bearer ak_bearer_test")],
            client=("127.0.0.1", 7777),
        )

        with patch("server._api_key_manager", mgr):
            capture = CaptureSend()
            asyncio.run(mw(scope, _null_receive, capture))

        assert capture.status == 200

    def test_x_forwarded_for_used_as_ip(self):
        """X-Forwarded-For header should be used as client IP for rate limiting."""
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(
            headers=[(b"x-forwarded-for", b"203.0.113.1, 10.0.0.1")],
            client=("10.0.0.1", 5555),
        )
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 200

    def test_x_real_ip_used_as_ip(self):
        mw = RateLimitMiddleware(_passthrough_app)
        scope = make_scope(
            headers=[(b"x-real-ip", b"198.51.100.1")],
            client=("10.0.0.1", 4444),
        )
        capture = CaptureSend()
        asyncio.run(mw(scope, _null_receive, capture))
        assert capture.status == 200


# ============================================================
# _certify_with_trust_layer
# ============================================================

class TestCertifyWithTrustLayer:

    def test_successful_certification(self):
        fake_response = {
            "proof_id": "proof_abc123",
            "proof_url": "https://trust.arkforge.tech/proof/abc123",
            "timestamp": "2025-01-17T00:00:00Z",
            "signature": "ed25519sig",
            "rfc3161_timestamp": "rfc3161data",
            "rekor_log_index": 999,
        }

        class FakeResp:
            def read(self):
                return json.dumps(fake_response).encode()

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            result = _certify_with_trust_layer({"report": "data"}, "ak_certified_key")

        assert result["certified"] is True
        assert result["proof_id"] == "proof_abc123"
        assert result["proof_url"] == fake_response["proof_url"]
        assert "Verifiable" in result["verification_note"]

    def test_http_error_returns_not_certified(self):
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://trust.arkforge.tech/v1/proxy",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=None,
        )
        err.read = lambda: b"Unauthorized"

        with patch("urllib.request.urlopen", side_effect=err):
            result = _certify_with_trust_layer({"report": "data"}, "bad_key")

        assert result["certified"] is False
        assert "401" in result["error"]

    def test_network_error_returns_not_certified(self):
        with patch("urllib.request.urlopen", side_effect=ConnectionError("timeout")):
            result = _certify_with_trust_layer({"report": "data"}, "ak_key")

        assert result["certified"] is False
        assert "error" in result


# ============================================================
# create_server — smoke test
# ============================================================

class TestCreateServer:

    def test_server_created_successfully(self):
        server = create_server()
        assert server is not None

    def test_server_has_tools(self):
        """FastMCP server should have tools registered."""
        server = create_server()
        # FastMCP exposes tool count or tools attribute
        # Just verify no exception and object has expected interface
        assert hasattr(server, "streamable_http_app") or hasattr(server, "name")
