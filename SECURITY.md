# Security Policy

## Overview

Gemini Sentinel is a security analysis tool designed to help identify vulnerabilities in code. As a security-focused application, we take the security of this tool itself very seriously.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | :white_check_mark: |

## Security Features

### 1. File Security
- **Restrictive Permissions**: All files are protected with owner-only access (600/700)
- **Secret Detection**: Automatic redaction of API keys, tokens, and credentials
- **Secure Defaults**: All sensitive data excluded from version control

### 2. Server Security
- **CSP Headers**: Content Security Policy prevents XSS attacks
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, CORS policies
- **Input Validation**: File size limits, payload validation, and sanitization
- **API Key Protection**: Keys never exposed to client, server-side only

### 3. Network Security
- **Same-Origin Policy**: Resources loaded only from trusted sources
- **No External Dependencies**: Minimal attack surface
- **HTTPS Required**: Production deployments must use HTTPS

## Setting Up Security

### Initial Setup

1. **Clone and secure the repository:**
   ```bash
   git clone <repo-url>
   cd Gemini-Sentinel-OpenClaw-Security-Agent
   ./scripts/setup-permissions.sh
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   chmod 400 .env
   # Edit .env with your API key
   ```

3. **Verify security configuration:**
   ```bash
   ./scripts/verify-security.sh
   ```

### File Permission Scheme

| Resource Type | Permissions | Description |
|--------------|-------------|-------------|
| Source files | 600 (rw-------) | Owner can read/write, others have no access |
| Directories | 700 (rwx------) | Owner can traverse, others cannot |
| Scripts | 700 (rwx------) | Owner can execute, others cannot |
| Secrets (.env, .pem, .key) | 400 (r--------) | Owner can read only, others have no access |

### API Key Security

**CRITICAL**: Your Gemini API key must be protected.

1. **Never commit API keys** to version control
2. **Use environment variables** (`.env` file)
3. **Set restrictive permissions**: `chmod 400 .env`
4. **Rotate keys regularly** (at least quarterly)
5. **Use different keys** for development and production
6. **Monitor usage** in your API provider dashboard

```bash
# Secure your .env file
chmod 400 .env

# Verify it's not readable by others
ls -la .env
# Should show: -r-------- 1 you you ... .env
```

## Reporting a Vulnerability

If you discover a security vulnerability in Gemini Sentinel, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly
3. **DO** email the maintainer directly with details
4. **DO** provide steps to reproduce if possible

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)
- Your contact information

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

## Security Best Practices

### For Users

1. **Keep dependencies updated**: Run `npm audit` regularly
2. **Review generated analyses**: Ensure no secrets in output
3. **Use HTTPS in production**: Never expose API over HTTP
4. **Limit file access**: Only analyze code you trust
5. **Monitor server logs**: Watch for unusual patterns

### For Developers

1. **Follow principle of least privilege**: Minimal permissions required
2. **Validate all inputs**: Never trust user data
3. **Sanitize outputs**: Prevent injection attacks
4. **Use parameterized queries**: Avoid SQL injection (if DB added)
5. **Keep secrets out of logs**: Redact sensitive data
6. **Review code changes**: All PRs require security review

### Security Checklist for Deployment

- [ ] Environment variables configured and secured (chmod 400)
- [ ] API keys are production keys (not development)
- [ ] HTTPS enabled with valid certificate
- [ ] File permissions set correctly (run setup-permissions.sh)
- [ ] Security headers enabled in server configuration
- [ ] Rate limiting configured
- [ ] Logging enabled and monitored
- [ ] Backup and disaster recovery plan in place
- [ ] Security verification passed (run verify-security.sh)

## Known Security Considerations

### Current Implementation

1. **Local execution**: Server runs locally, no authentication by default
2. **API key in environment**: Secure for local use, consider secrets manager for production
3. **File system access**: Server reads files from disk, ensure proper OS-level permissions

### Production Deployment Recommendations

If deploying to production, add:

1. **Authentication**: Add API token validation
2. **Rate limiting**: Prevent abuse
3. **IP whitelisting**: Restrict access to known IPs
4. **Secrets manager**: Use Vault, AWS Secrets Manager, etc.
5. **Audit logging**: Track all access and changes
6. **DDoS protection**: Use Cloudflare or similar
7. **Container security**: If using Docker, scan images

## Security Tools

This repository includes scripts to help maintain security:

- `scripts/setup-permissions.sh` - Configure file permissions
- `scripts/verify-security.sh` - Verify security settings

Run these regularly to ensure security posture is maintained.

## Compliance

This tool processes code that may contain sensitive information:

- **Data Privacy**: Ensure code analyzed complies with privacy regulations
- **Confidentiality**: Use secure channels for sharing analysis results
- **Access Control**: Only authorized personnel should access the server
- **Audit Trail**: Consider logging analysis requests for compliance

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Gemini API Security](https://ai.google.dev/docs)

## Questions?

For security questions or concerns, please contact the repository maintainer.

---

**Last Updated**: 2026-02-04  
**Version**: 1.0
