# Security Setup Checklist

Use this checklist to ensure your Gemini Sentinel installation is properly secured.

## Initial Setup

- [ ] Clone repository
- [ ] Run `./scripts/setup-permissions.sh`
- [ ] Create `.env` file from `.env.example`
- [ ] Add your `GEMINI_API_KEY` to `.env`
- [ ] Secure `.env` file: `chmod 400 .env`
- [ ] Run `./scripts/verify-security.sh`

## File Security

- [ ] All source files are `600` (owner rw, others none)
- [ ] All directories are `700` (owner rwx, others none)
- [ ] Scripts are `700` (owner rwx, others none)
- [ ] `.env` file is `400` (owner r, others none)
- [ ] `.security-lock` file exists
- [ ] No world-readable files exist
- [ ] No group-readable files exist

## Environment Variables

- [ ] `GEMINI_API_KEY` is set
- [ ] `PORT` is configured (default: 8787)
- [ ] `NODE_ENV` is set appropriately
- [ ] `API_AUTH_TOKEN` is set for production (optional but recommended)
- [ ] `ALLOWED_IPS` is configured for production (optional but recommended)
- [ ] No API keys in source code
- [ ] No API keys in git history

## Server Security

- [ ] Security headers enabled
- [ ] CSP policy configured
- [ ] HSTS header enabled
- [ ] X-Frame-Options set to DENY
- [ ] IP whitelisting configured (if needed)
- [ ] API authentication enabled (if needed)
- [ ] Input validation active
- [ ] File size limits configured

## Access Control

- [ ] Only authorized user can read/write files
- [ ] Server runs as appropriate user (not root)
- [ ] API endpoint requires authentication (in production)
- [ ] IP whitelist configured (in production)

## Secrets Management

- [ ] API keys never committed to git
- [ ] `.gitignore` includes `.env*` files
- [ ] `.gitignore` includes `*.key`, `*.pem`, etc.
- [ ] Secret redaction enabled in analysis
- [ ] No hardcoded credentials in code

## Production Deployment (Additional)

- [ ] HTTPS enabled with valid certificate
- [ ] Firewall rules configured
- [ ] Rate limiting enabled
- [ ] Logging enabled
- [ ] Monitoring configured
- [ ] Backup plan in place
- [ ] Disaster recovery plan documented
- [ ] Security updates applied
- [ ] Dependencies audited (`npm audit`)

## Ongoing Maintenance

- [ ] Regular security verification (`./scripts/verify-security.sh`)
- [ ] API key rotation (quarterly minimum)
- [ ] Dependency updates (monthly)
- [ ] Security audit (quarterly)
- [ ] Review access logs (weekly)
- [ ] Monitor API usage (daily)

## Verification Commands

```bash
# Run security setup
./scripts/setup-permissions.sh

# Verify security configuration
./scripts/verify-security.sh

# Check file permissions
ls -la

# Check .env permissions
ls -la .env

# Check for secrets in git
git log -p | grep -i "api.key\|password\|secret"

# Audit dependencies
npm audit

# Check security headers (when server running)
curl -I http://localhost:8787/api/health
```

## Emergency Response

If security is compromised:

1. **Immediately rotate API keys**
   - Generate new Gemini API key
   - Update `.env` file
   - Restart server

2. **Review access logs**
   - Check for unauthorized access
   - Document incident

3. **Verify file integrity**
   - Run `./scripts/verify-security.sh`
   - Check for unauthorized changes

4. **Restore from backup if needed**

## Notes

- Date security setup completed: ___________
- Last security verification: ___________
- Last API key rotation: ___________
- Next scheduled review: ___________

---

**Status**: ⬜ Not Started | ⏳ In Progress | ✅ Complete

Update this checklist whenever making security-related changes.
