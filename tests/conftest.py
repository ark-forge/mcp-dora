"""Shared fixtures for DORA MCP test suite."""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server import RateLimiter, _current_plan


@pytest.fixture(autouse=True)
def isolate_rate_limiter_persistence(tmp_path):
    """Redirect RateLimiter persistence to tmp_path to avoid polluting data/."""
    original_path = RateLimiter._PERSIST_PATH
    RateLimiter._PERSIST_PATH = tmp_path / "rate_limits.json"
    yield
    RateLimiter._PERSIST_PATH = original_path


@pytest.fixture(autouse=True)
def set_certified_plan():
    """Set plan to 'certified' for all tests so paywall gates don't block tool tests.

    Tests that specifically test paywall behavior should call
    _current_plan.set('free') at the start of the test.
    """
    token = _current_plan.set("certified")
    yield
    _current_plan.reset(token)


def make_project(tmp_path, files: dict) -> str:
    """Create a temp project with given files. Returns path string."""
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return str(tmp_path)
