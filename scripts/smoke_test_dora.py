#!/usr/bin/env python3
"""
smoke_test_dora.py — Smoke tests for the deployed MCP DORA scanner.

Runs against the local MCP server (default: http://127.0.0.1:8091).

Protocol: MCP Streamable HTTP JSON-RPC 2.0
  1. POST /mcp (no session) → initialize → get Mcp-Session-Id header
  2. POST /mcp (with session) → tools/call classify_entity
  3. POST /mcp (with session) → tools/call scan_project
  4. POST /mcp (with session) → tools/call generate_report

Exit 0 if all 3 tool tests pass, exit 1 on any failure.

Usage:
    python3 scripts/smoke_test_dora.py [--base-url http://127.0.0.1:8091]
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

PASS = "PASS"
FAIL = "FAIL"


def _post(url: str, payload: dict, headers: dict = None, timeout: int = 15):
    """POST JSON-RPC. Returns (status_code, response_headers, body_dict)."""
    data = json.dumps(payload).encode("utf-8")
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = json.loads(resp.read().decode("utf-8"))
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"http_error": e.code}
        return e.code, {}, body
    except Exception as exc:
        return None, {}, {"exception": str(exc)}


def initialize_session(mcp_url: str):
    """Call MCP initialize to get a session ID. Returns session_id or None."""
    code, headers, body = _post(mcp_url, {
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "1.0"},
        },
    })
    if code != 200:
        print(f"  [init] FAILED — HTTP {code}, body={body}")
        return None
    session_id = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
    return session_id


def call_tool(mcp_url: str, session_id: str, tool: str, arguments: dict, timeout: int = 15):
    """Call a MCP tool. Returns (status_code, result_dict)."""
    h = {"Mcp-Session-Id": session_id}
    code, _, body = _post(mcp_url, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }, headers=h, timeout=timeout)

    if code != 200:
        return code, body

    # Extract result from JSON-RPC content array
    content = body.get("result", {}).get("content", [])
    if content and isinstance(content, list):
        text = content[0].get("text", "{}")
        try:
            return code, json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return code, {"raw": text}
    return code, body


def run_tests(base_url: str) -> bool:
    mcp_url = f"{base_url.rstrip('/')}/mcp"
    results = []
    all_passed = True

    # ------------------------------------------------------------------
    # Init: establish MCP session
    # ------------------------------------------------------------------
    print(f"\n[Init] MCP initialize → {mcp_url}")
    session_id = initialize_session(mcp_url)
    if not session_id:
        print(f"  FAIL — Could not initialize MCP session")
        return False
    print(f"  OK — session_id: {session_id[:16]}...")

    # ------------------------------------------------------------------
    # Test 1: classify_entity(credit_institution)
    # ------------------------------------------------------------------
    print(f"\n[Test 1] classify_entity(credit_institution)")
    code, body = call_tool(mcp_url, session_id, "classify_entity", {"entity_type": "credit_institution"})
    articles_count = body.get("applicable_articles_count", 0) if isinstance(body, dict) else 0
    if code == 200 and articles_count > 0:
        label = body.get("label", "?")
        tlpt = body.get("tlpt_required", "?")
        print(f"  {PASS} — applicable_articles={articles_count}, label={label!r}, tlpt_required={tlpt}")
        results.append(True)
    else:
        print(f"  {FAIL} — HTTP {code}, body={json.dumps(body)[:300]}")
        print("  Expected: applicable_articles_count > 0")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Test 2: scan_project(/tmp)
    # ------------------------------------------------------------------
    print(f"\n[Test 2] scan_project(/tmp)")
    code, body = call_tool(mcp_url, session_id, "scan_project", {"project_path": "/tmp"})
    has_findings = isinstance(body, dict) and "findings" in body
    files_scanned = body.get("files_scanned", -1) if isinstance(body, dict) else -1
    if code == 200 and has_findings and files_scanned >= 0:
        deps_count = len(body.get("findings", {}).get("third_party_dependencies", {}))
        gaps_count = len(body.get("gaps", []))
        print(f"  {PASS} — files_scanned={files_scanned}, deps={deps_count}, gaps={gaps_count}")
        results.append(True)
    else:
        print(f"  {FAIL} — HTTP {code}, has_findings={has_findings}, files_scanned={files_scanned}")
        print(f"  body={json.dumps(body)[:300]}")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Test 3: generate_report(/tmp)
    # ------------------------------------------------------------------
    print(f"\n[Test 3] generate_report(/tmp)")
    code, body = call_tool(mcp_url, session_id, "generate_report", {"project_path": "/tmp"})
    report_type = body.get("report_type", "") if isinstance(body, dict) else ""
    if code == 200 and "DORA" in report_type:
        score = body.get("combined_score_pct", "?")
        readiness = body.get("readiness", "?")
        in_force = body.get("in_force", "?")
        print(f"  {PASS} — score={score}%, readiness={readiness!r}, in_force={in_force!r}")
        results.append(True)
    else:
        print(f"  {FAIL} — HTTP {code}, report_type={report_type!r}")
        print(f"  body={json.dumps(body)[:300]}")
        results.append(False)
        all_passed = False

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    passed = sum(results)
    total = len(results)
    print(f"\n{'='*50}")
    print(f"  Smoke tests: {passed}/{total} passed")
    if all_passed:
        print("  Result: ALL PASS (3/3)")
    else:
        print("  Result: FAILED")
    print(f"{'='*50}\n")

    return all_passed


def main():
    parser = argparse.ArgumentParser(description="Smoke tests for MCP DORA scanner")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8091",
        help="Base URL of the MCP DORA service (default: http://127.0.0.1:8091)",
    )
    args = parser.parse_args()

    print("MCP DORA — Smoke Test")
    print(f"Target: {args.base_url}")

    success = run_tests(args.base_url)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
