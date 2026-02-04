#!/bin/bash
# Verify File Security Script
# Checks that security permissions are correctly applied

set -e

echo "🔍 Security Verification Check"
echo "=============================="
echo ""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OWNER=$(whoami)
ISSUES=0

echo "Checking permissions for owner: $OWNER"
echo ""

# Check if security lock file exists
if [ ! -f ".security-lock" ]; then
  echo "⚠️  WARNING: Security lock file not found"
  echo "   Run: ./scripts/setup-permissions.sh"
  ISSUES=$((ISSUES + 1))
else
  echo "✓ Security lock file exists"
fi

# Check for world-readable source files
echo ""
echo "Checking for world-readable source files..."
WORLD_READABLE=$(find . -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/dist/*" \
  ! -path "*/.git/*" \
  -perm /004 2>/dev/null | wc -l)

if [ "$WORLD_READABLE" -gt 0 ]; then
  echo "⚠️  Found $WORLD_READABLE world-readable files"
  echo "   These files should be secured:"
  find . -type f \
    ! -path "*/node_modules/*" \
    ! -path "*/dist/*" \
    ! -path "*/.git/*" \
    -perm /004 2>/dev/null | head -5
  ISSUES=$((ISSUES + 1))
else
  echo "✓ No world-readable source files found"
fi

# Check for group-readable source files
echo ""
echo "Checking for group-readable source files..."
GROUP_READABLE=$(find . -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/dist/*" \
  ! -path "*/.git/*" \
  -perm /040 2>/dev/null | wc -l)

if [ "$GROUP_READABLE" -gt 0 ]; then
  echo "⚠️  Found $GROUP_READABLE group-readable files"
  ISSUES=$((ISSUES + 1))
else
  echo "✓ No group-readable source files found"
fi

# Check for .env files
echo ""
echo "Checking for environment files..."
if ls .env* >/dev/null 2>&1; then
  for envfile in .env*; do
    if [ -f "$envfile" ] && [ "$envfile" != ".env.example" ]; then
      PERMS=$(stat -c %a "$envfile" 2>/dev/null || stat -f %A "$envfile" 2>/dev/null)
      if [ "$PERMS" != "400" ] && [ "$PERMS" != "600" ]; then
        echo "⚠️  $envfile has insecure permissions: $PERMS"
        echo "   Should be 400 or 600"
        ISSUES=$((ISSUES + 1))
      else
        echo "✓ $envfile is properly secured ($PERMS)"
      fi
    fi
  done
else
  echo "✓ No environment files found (use .env.example as template)"
fi

# Summary
echo ""
echo "=============================="
if [ $ISSUES -eq 0 ]; then
  echo "✅ Security verification PASSED"
  echo "   All files are properly secured"
else
  echo "❌ Security verification FAILED"
  echo "   Found $ISSUES security issue(s)"
  echo ""
  echo "   Run: ./scripts/setup-permissions.sh"
  exit 1
fi
echo ""
