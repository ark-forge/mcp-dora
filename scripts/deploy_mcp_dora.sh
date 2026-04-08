#!/usr/bin/env bash
# deploy_mcp_dora.sh — Deploy MCP DORA to production with gates + staged rollout + rollback
#
# Usage: ./scripts/deploy_mcp_dora.sh [--minor|--major] [--force] [--skip-smoke]
#
# Flags:
#   --force        Bypass CI GitHub check
#   --skip-smoke   Skip post-deploy smoke test (use for emergency hotfixes)
#   --minor        Bump minor version (1.0.x → 1.1.0)
#   --major        Bump major version (1.x.x → 2.0.0)
#   (default)      Bump patch (1.0.2 → 1.0.3)
#
# Phases:
#   1  — Gates (CI, pytest ≥80%, smoke pre-deploy)
#   2  — Version bump (pyproject.toml + server.py __version__)
#   3  — Deploy local (systemctl restart + health × 3 + canary)
#   4  — Deploy OVH (SKIPPED — service runs local only)
#   5  — Smoke test (smoke_test_dora.py: 3/3 classify/scan/report)
#   6  — Release (git tag + push)
#   7  — PyPI publish (non-blocking)
#   8  — Telegram notification

set -euo pipefail

# --- Configuration ---
REPO_DIR="/opt/claude-ceo/workspace/mcp-servers/dora"
SERVICE_MCP="mcp-dora"
LOCAL_HEALTH_URL="http://127.0.0.1:8201/health"
OVH_ENABLED=false
LOG_FILE="/opt/claude-ceo/logs/deploy_mcp_dora.log"
SMOKE_TEST_SCRIPT="$REPO_DIR/scripts/smoke_test_dora.py"

# --- Args ---
VERSION_BUMP="patch"
FORCE_CI=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --minor)      VERSION_BUMP="minor" ;;
        --major)      VERSION_BUMP="major" ;;
        --force)      FORCE_CI=true ;;
        --skip-smoke) SKIP_SMOKE=true ;;
    esac
done

# --- Logging ---
mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; telegram_notify "Deploy FAILED: $*"; exit 1; }

# --- Telegram notification ---
telegram_notify() {
    local msg="[MCP DORA Deploy] $1"
    local token="" chat_ids=""
    if token=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('bot_token', ''))
" 2>/dev/null) && [ -n "$token" ]; then
        chat_ids=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('chat_ids', ''))
" 2>/dev/null)
    fi
    if [ -z "$token" ] || [ -z "$chat_ids" ]; then
        log "WARN: Telegram not configured, skipping notification"
        return 0
    fi
    for chat_id in $(echo "$chat_ids" | tr ',' ' '); do
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat_id}&text=${msg}&parse_mode=Markdown" > /dev/null 2>&1 || true
    done
}

# --- Version bump helper ---
bump_version() {
    local current="$1" bump="$2"
    local major minor patch
    major=$(echo "$current" | cut -d. -f1 | tr -d 'v')
    minor=$(echo "$current" | cut -d. -f2)
    patch=$(echo "$current" | cut -d. -f3)
    case "$bump" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
    esac
}

# --- Ensure we're on main ---
cd "$REPO_DIR"
CURRENT_BRANCH=$(git -C /opt/claude-ceo rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    fail "Not on main branch (current: $CURRENT_BRANCH). Switch to main before deploying."
fi

log "=== MCP DORA Deploy — $(date -u) ==="
log "Branch: main | Version bump: $VERSION_BUMP | Force CI: $FORCE_CI | Skip smoke: $SKIP_SMOKE"

# ============================================================
# PHASE 1 — GATES
# ============================================================
log "--- Phase 1: Gates ---"

# Gate 1 — CI GitHub
if [ "$FORCE_CI" = false ]; then
    log "Gate 1/3: CI GitHub on main..."
    CI_STATUS=$(gh run list --repo ark-forge/mcp-dora --branch main --limit 1 \
        --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "")
    if [ -z "$CI_STATUS" ] || [ "$CI_STATUS" = "null" ]; then
        log "Gate 1/3: No CI runs found — bypassing (WARNING)"
    elif [ "$CI_STATUS" != "success" ]; then
        fail "CI gate FAILED — last run: '$CI_STATUS'. Use --force to bypass."
    else
        log "Gate 1/3: CI OK (last run: success)"
    fi
else
    log "Gate 1/3: CI bypassed (--force)"
fi

# Gate 2 — pytest + coverage 80%
log "Gate 2/3: pytest + coverage 80%..."
if ! python3 -m pytest tests/ -q --cov=server --cov-fail-under=80 --tb=short >> "$LOG_FILE" 2>&1; then
    fail "pytest gate FAILED (coverage < 80% or tests failing)"
fi
log "Gate 2/3: pytest OK (coverage >= 80%)"

# Gate 3 — smoke pre-deploy (only if service is running)
log "Gate 3/3: smoke pre-deploy health check..."
PRE_HEALTH=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" 2>/dev/null || echo "")
if [ -z "$PRE_HEALTH" ]; then
    log "Gate 3/3: service not running — skipping pre-deploy health (WARNING)"
else
    PRE_STATUS=$(echo "$PRE_HEALTH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if d.get('status') == 'ok' else 'unexpected')
except:
    print('error')
" 2>/dev/null || echo "error")
    if [ "$PRE_STATUS" = "ok" ]; then
        log "Gate 3/3: pre-deploy health OK"
    else
        log "Gate 3/3: pre-deploy health returned '$PRE_STATUS' — WARNING (non-blocking)"
    fi
fi

log "All gates PASSED"

# ============================================================
# PHASE 2 — VERSION BUMP
# ============================================================
log "--- Phase 2: Version bump ---"

CURRENT_VERSION=$(grep -oP '(?<=^version = ")[^"]+' pyproject.toml 2>/dev/null || echo "")
if [ -z "$CURRENT_VERSION" ]; then
    fail "Could not read version from pyproject.toml"
fi
NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$VERSION_BUMP")
log "Version: $CURRENT_VERSION → $NEW_VERSION"

LAST_TAG=$(git -C /opt/claude-ceo tag --sort=-v:refname | grep "mcp-dora" | head -1 || echo "")
if [ -z "$LAST_TAG" ]; then LAST_TAG="mcp-dora-v0.0.0"; fi
NEW_TAG="mcp-dora-v${NEW_VERSION}"
CHANGELOG=$(git -C /opt/claude-ceo log --oneline --no-merges -- workspace/mcp-servers/dora/ 2>/dev/null | head -20 | sed 's/^/• /' || echo "• Initial release")

PREV_COMMIT=$(git -C /opt/claude-ceo rev-parse HEAD)
log "Previous commit (rollback point): $PREV_COMMIT"

git -C /opt/claude-ceo pull origin main >> "$LOG_FILE" 2>&1

# Re-read after pull
CURRENT_VERSION=$(grep -oP '(?<=^version = ")[^"]+' pyproject.toml 2>/dev/null || echo "$CURRENT_VERSION")
if [ "$CURRENT_VERSION" != "$NEW_VERSION" ]; then
    sed -i "s/^version = .*/version = \"$NEW_VERSION\"/" pyproject.toml
    if grep -q '__version__' server.py 2>/dev/null; then
        sed -i "s/^__version__ = .*/__version__ = \"$NEW_VERSION\"/" server.py
        git -C /opt/claude-ceo add workspace/mcp-servers/dora/pyproject.toml workspace/mcp-servers/dora/server.py
        log "Version bumped in pyproject.toml + server.py"
    else
        git -C /opt/claude-ceo add workspace/mcp-servers/dora/pyproject.toml
        log "Version bumped in pyproject.toml"
    fi
    git -C /opt/claude-ceo commit -m "chore(dora): bump version to $NEW_VERSION" >> "$LOG_FILE" 2>&1
    git -C /opt/claude-ceo push origin main >> "$LOG_FILE" 2>&1
    log "Version commit pushed"
else
    log "Version already at $NEW_VERSION — no bump needed"
fi

NEW_COMMIT=$(git -C /opt/claude-ceo rev-parse HEAD)
log "Local commit: $NEW_COMMIT"

# ============================================================
# PHASE 3 — DEPLOY LOCAL
# ============================================================
log "--- Phase 3a: Deploy local (restart $SERVICE_MCP) ---"
sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || \
    fail "Could not restart $SERVICE_MCP — check systemctl status $SERVICE_MCP"
sleep 3

# Phase 3b — health check × 3 × 5s
log "--- Phase 3b: Local health check (3 attempts × 5s) ---"
LOCAL_HEALTHY=false
for i in 1 2 3; do
    sleep 5
    LOCAL_STATUS=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if d.get('status') == 'ok' else 'unexpected')
except:
    print('error')
" 2>/dev/null || echo "error")
    log "Phase 3b attempt $i/3: status=$LOCAL_STATUS"
    if [ "$LOCAL_STATUS" = "ok" ]; then
        LOCAL_HEALTHY=true
        break
    fi
done

if [ "$LOCAL_HEALTHY" = false ]; then
    log "Phase 3b FAILED — local not healthy after restart"
    git -C /opt/claude-ceo reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || true
    fail "Phase 3b FAILED — rolled back to $PREV_COMMIT"
fi
log "Phase 3b OK — local healthy"

# Phase 3c — canary: verify DORA-specific response fields
log "--- Phase 3c: Canary check (classify_entity response) ---"
CANARY_RESP=$(python3 -c "
import sys, json, urllib.request

payload = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
    'params': {'name': 'classify_entity', 'arguments': {'entity_type': 'credit_institution'}}
}).encode()

try:
    req = urllib.request.Request(
        'http://127.0.0.1:8091/mcp/',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    resp = urllib.request.urlopen(req, timeout=10)
    d = json.loads(resp.read())
    result_text = d.get('result', {}).get('content', [{}])[0].get('text', '{}')
    result = json.loads(result_text) if isinstance(result_text, str) else result_text
    print('ok' if result.get('applicable_articles_count', 0) > 0 else 'missing')
except Exception as e:
    print(f'error:{e}')
" 2>/dev/null || echo "error")

if echo "$CANARY_RESP" | grep -q "^ok"; then
    log "Phase 3c OK — classify_entity canary confirmed"
elif echo "$CANARY_RESP" | grep -q "error"; then
    log "Phase 3c WARN — canary not reachable or malformed (non-blocking): $CANARY_RESP"
else
    log "Phase 3c WARN — unexpected canary response: $CANARY_RESP (non-blocking)"
fi

# ============================================================
# PHASE 4 — DEPLOY OVH (SKIPPED)
# ============================================================
log "--- Phase 4: Deploy OVH — SKIPPED (OVH_ENABLED=false, service runs local only) ---"

# ============================================================
# PHASE 5 — SMOKE TEST
# ============================================================
SMOKE_RESULT="SKIPPED"
if [ "$SKIP_SMOKE" = true ]; then
    log "--- Phase 5: Smoke test SKIPPED (--skip-smoke) ---"
else
    log "--- Phase 5: Smoke test (3/3 calls) ---"
    if [ ! -f "$SMOKE_TEST_SCRIPT" ]; then
        log "WARN: Smoke test script not found at $SMOKE_TEST_SCRIPT — skipping"
    else
        SMOKE_LOG="$LOG_FILE.smoke"
        if python3 "$SMOKE_TEST_SCRIPT" \
               --base-url "http://127.0.0.1:8091" \
               2>&1 | tee -a "$SMOKE_LOG" | tail -8; then
            log "Phase 5: Smoke test PASSED (3/3)"
            SMOKE_RESULT="PASSED"
        else
            SMOKE_EXIT=${PIPESTATUS[0]}
            log "Phase 5: Smoke test FAILED (exit $SMOKE_EXIT)"
            SMOKE_RESULT="FAILED"
            git -C /opt/claude-ceo reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
            sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || true
            fail "Smoke test FAILED — rolled back to $PREV_COMMIT"
        fi
    fi
fi

# ============================================================
# PHASE 6 — RELEASE
# ============================================================
log "--- Phase 6: Release ---"
git -C /opt/claude-ceo tag "$NEW_TAG"
git -C /opt/claude-ceo push origin "$NEW_TAG" >> "$LOG_FILE" 2>&1
log "Tag $NEW_TAG pushed"

# ============================================================
# PHASE 7 — PYPI (non-blocking)
# ============================================================
log "--- Phase 7: PyPI publish ---"
PYPI_RESULT="skipped"
if rm -rf dist/ && python3 -m build -q >> "$LOG_FILE" 2>&1; then
    TWINE_OUT=$(python3 -m twine upload dist/* 2>&1)
    echo "$TWINE_OUT" >> "$LOG_FILE"
    if echo "$TWINE_OUT" | grep -q "View at:"; then
        log "PyPI publish OK: mcp-dora $NEW_VERSION"
        PYPI_RESULT="$CURRENT_VERSION → $NEW_VERSION"
    elif echo "$TWINE_OUT" | grep -q "already exists"; then
        log "WARN: $NEW_VERSION already on PyPI — skipping (idempotent)"
        PYPI_RESULT="already exists"
    else
        log "WARN: PyPI publish failed — $(echo "$TWINE_OUT" | tail -3)"
        PYPI_RESULT="FAILED (upload)"
    fi
else
    log "WARN: PyPI build failed (non-blocking)"
    PYPI_RESULT="FAILED (build)"
fi

# ============================================================
# PHASE 8 — TELEGRAM NOTIFICATION
# ============================================================
log "--- Phase 8: Notification ---"
SMOKE_MSG="smoke: ${SMOKE_RESULT}"
NOTIFY_MSG="mcp-dora v${CURRENT_VERSION} → v${NEW_VERSION} OK | ${SMOKE_MSG} | pypi: ${PYPI_RESULT}\n\n${CHANGELOG}"
telegram_notify "$NOTIFY_MSG"
log "Telegram notification sent"

log "=== Deploy $NEW_TAG COMPLETE ==="
echo ""
echo "  mcp-dora $NEW_TAG deployed successfully"
echo "  Health: $LOCAL_HEALTH_URL"
echo "  MCP port: 8091"
echo "  Changelog since $LAST_TAG:"
echo "$CHANGELOG"
