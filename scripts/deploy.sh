#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Deploy Code Security Scanner to MCPize Marketplace
# ============================================================
# Prerequisites:
#   1. Node.js / npm installed
#   2. MCPize account: https://mcpize.com (sign up, ~1 min)
#   3. Set your GITHUB_URL below
# ============================================================

GITHUB_URL="${GITHUB_URL:-https://github.com/yourusername/code-scanner-mcp}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Step 1: Installing MCPize CLI"
npm install -g mcpize

echo ""
echo "==> Step 2: Logging in to MCPize"
echo "    (opens browser for authentication)"
mcpize login

echo ""
echo "==> Step 3: Linking project"
cd "$SCRIPT_DIR"
mcpize link || mcpize init code-scanner

echo ""
echo "==> Step 4: Running pre-deploy checks"
mcpize doctor

echo ""
echo "==> Step 5: Publishing to marketplace"
echo "    This will auto-generate SEO, logo, and list as free tier."
echo "    Run with --pricing to set Pro tier:"
echo "      mcpize publish --auto --pricing \"Free 10 scans/day, Pro \\\$29/mo unlimited\""
mcpize publish --auto

echo ""
echo "============================================"
echo "✅ Listing live at: https://mcpize.com/mcp/code-scanner"
echo ""
echo "Next steps:"
echo "  1. Go to https://mcpize.com/developer/servers/code-scanner/settings"
echo "  2. Enable monetization to lock Founding Member rate (before June 10)"
echo "  3. Set your Stripe Connect for payouts"
echo "============================================"
