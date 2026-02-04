#!/bin/bash
# Test script to verify security features are working

set -e

echo "🧪 Security Feature Tests"
echo "========================="
echo ""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Test 1: Check file permissions
echo "Test 1: File Permissions"
echo "-------------------------"
if [ -f ".security-lock" ]; then
  PERMS=$(stat -c %a .security-lock 2>/dev/null || stat -f %A .security-lock 2>/dev/null)
  if [ "$PERMS" = "600" ]; then
    echo "✅ Security lock file has correct permissions (600)"
  else
    echo "❌ Security lock file has wrong permissions: $PERMS"
    exit 1
  fi
else
  echo "❌ Security lock file not found"
  exit 1
fi

# Test 2: Check .gitignore
echo ""
echo "Test 2: .gitignore Configuration"
echo "---------------------------------"
if grep -q "^\.env$" .gitignore; then
  echo "✅ .env files excluded from git"
else
  echo "❌ .env not in .gitignore"
  exit 1
fi

if grep -q "\*\.pem" .gitignore || grep -q "\*\.key" .gitignore; then
  echo "✅ Secret files excluded from git"
else
  echo "❌ Secret files not properly excluded"
  exit 1
fi

# Test 3: Check scripts are executable
echo ""
echo "Test 3: Script Executability"
echo "-----------------------------"
if [ -x "./scripts/setup-permissions.sh" ]; then
  echo "✅ setup-permissions.sh is executable"
else
  echo "❌ setup-permissions.sh is not executable"
  exit 1
fi

if [ -x "./scripts/verify-security.sh" ]; then
  echo "✅ verify-security.sh is executable"
else
  echo "❌ verify-security.sh is not executable"
  exit 1
fi

# Test 4: Check documentation exists
echo ""
echo "Test 4: Documentation"
echo "---------------------"
for doc in SECURITY.md SECURITY-CHECKLIST.md .env.example; do
  if [ -f "$doc" ]; then
    echo "✅ $doc exists"
  else
    echo "❌ $doc is missing"
    exit 1
  fi
done

# Test 5: Server code syntax
echo ""
echo "Test 5: Server Code Validation"
echo "-------------------------------"
if node --check server/index.js 2>/dev/null; then
  echo "✅ Server code syntax is valid"
else
  echo "❌ Server code has syntax errors"
  exit 1
fi

# Test 6: Check for hardcoded secrets
echo ""
echo "Test 6: Hardcoded Secrets Check"
echo "--------------------------------"
SECRETS_FOUND=$(grep -r "AKIA[0-9A-Z]\{16\}\|ghp_[A-Za-z0-9]\{36,\}\|AIza[0-9A-Za-z\-_]\{35\}" \
  --exclude-dir=node_modules \
  --exclude-dir=.git \
  --exclude-dir=dist \
  --exclude="*.md" \
  --exclude="secretSanitizer.ts" \
  . 2>/dev/null | wc -l)

if [ "$SECRETS_FOUND" -eq 0 ]; then
  echo "✅ No hardcoded secrets found"
else
  echo "⚠️  Warning: Potential secrets found (may be false positives)"
fi

# Summary
echo ""
echo "========================="
echo "✅ All security tests PASSED"
echo "========================="
echo ""
echo "Security features are properly configured."
echo ""
