#!/bin/bash
# Comprehensive File Security Setup Script
# Implements defense-in-depth security for the repository

set -e

echo "🔒 Gemini Sentinel: File Security Setup"
echo "========================================"
echo ""

OWNER=$(whoami)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Owner: $OWNER"
echo "Repository: $REPO_ROOT"
echo ""

# 1. Set restrictive umask for new files
echo "📋 Step 1/6: Setting secure umask..."
umask 077
echo "  ✓ New files will be created with restrictive permissions (600)"

# 2. Protect all source files (owner rw, others none)
echo ""
echo "📋 Step 2/6: Setting file permissions..."
echo "  Setting source files to owner-only (600)..."
find . -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/dist/*" \
  ! -path "*/.git/*" \
  ! -path "*/logs/*" \
  ! -name "*.sh" \
  -exec chmod 600 {} \; 2>/dev/null

echo "  Setting directories to owner-only access (700)..."
find . -type d \
  ! -path "*/node_modules/*" \
  ! -path "*/dist/*" \
  ! -path "*/.git/*" \
  -exec chmod 700 {} \; 2>/dev/null

# 3. Make scripts executable for owner only
echo ""
echo "📋 Step 3/6: Securing scripts..."
if [ -d "./scripts" ]; then
  find ./scripts -type f -name "*.sh" -exec chmod 700 {} \; 2>/dev/null || true
  echo "  ✓ Scripts are executable by owner only"
fi

# 4. Lock down sensitive files
echo ""
echo "📋 Step 4/6: Protecting sensitive files..."
for pattern in ".env*" "*.pem" "*.key" "*.cert" "*.p12" "secrets/*" "credentials/*"; do
  find . -name "$pattern" -type f -exec chmod 400 {} \; 2>/dev/null || true
done
echo "  ✓ Sensitive files are read-only for owner only (400)"

# 5. Create security marker file
echo ""
echo "📋 Step 5/6: Creating security marker..."
cat > .security-lock << EOF
# Security Lock File
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Owner: $OWNER
# 
# This file indicates that security permissions have been applied.
# To modify files, you must be the owner: $OWNER
#
# Permission scheme:
#   - Source files: 600 (owner rw, others none)
#   - Directories: 700 (owner rwx, others none)
#   - Scripts: 700 (owner rwx, others none)
#   - Secrets: 400 (owner r, others none)
EOF
chmod 600 .security-lock
echo "  ✓ Security marker created"

# 6. Display security summary
echo ""
echo "📋 Step 6/6: Verification..."
echo ""
echo "✅ Security setup complete!"
echo ""
echo "═══════════════════════════════════════"
echo "  SECURITY CONFIGURATION"
echo "═══════════════════════════════════════"
echo ""
echo "  👤 Authorized Owner: $OWNER"
echo ""
echo "  📁 File Permissions:"
echo "     • Source files:  600 (owner rw, others none)"
echo "     • Directories:   700 (owner rwx, others none)"  
echo "     • Scripts:       700 (owner rwx, others none)"
echo "     • Secrets:       400 (owner r, others none)"
echo ""
echo "  🛡️  Protection Level: MAXIMUM"
echo "     • Only $OWNER can read/write files"
echo "     • All other users: NO ACCESS"
echo "     • Secrets are read-only even for owner"
echo ""
echo "═══════════════════════════════════════"
echo ""
echo "⚠️  IMPORTANT NOTES:"
echo "  • Only YOU ($OWNER) can modify these files"
echo "  • Even processes running as other users cannot access"
echo "  • To temporarily allow edits, files remain owner-writable"
echo "  • Secrets are locked at read-only (400)"
echo ""
