
Note:
**README needs revision to more accurately reflect this tool as revised through AiStudio, Codex, and ClaudeCode**
See Dev notes in docs for deeper look into where this is heading. ~thanx!

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/drive/1RqKxAhjq29QfUvba1cxXhUiLT1-b16MG

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Start the local proxy (stores the API key server-side):
   `$env:GEMINI_API_KEY="YOUR_KEY"; npm run server` (Windows PowerShell)
3. Run the app:
   `npm run dev`
4. Open the app at `http://localhost:3000`.

## Production Build

1. Build the app:
   `npm run build`
2. Start the server (serves `dist/` + API proxy):
   `$env:GEMINI_API_KEY="YOUR_KEY"; npm run start`

## Security Notes

**⚠️ IMPORTANT: Complete Security Setup Before Use**

### Quick Security Setup

1. **Secure file permissions:**
   ```bash
   ./scripts/setup-permissions.sh
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   chmod 400 .env
   # Edit .env with your API key
   ```

3. **Verify security:**
   ```bash
   ./scripts/verify-security.sh
   ```

### Security Features

- **File Protection**: All files are owner-only access (600/700 permissions)
- **API Key Security**: The Gemini API key only lives on the server (client never sees it)
- **Secret Redaction**: Enabled by default to avoid sending secret-like strings in code samples
- **IP Whitelisting**: Optional IP-based access control (configure in .env)
- **Authentication**: Optional API token authentication for analyze endpoint
- **Security Headers**: CSP headers are enforced by the proxy server in production builds
- **HSTS**: Strict-Transport-Security header for HTTPS enforcement
- **Input Validation**: File size limits and payload validation

### Security Best Practices

1. **Never commit `.env` file** - it contains your API key
2. **Set restrictive permissions** on sensitive files (done automatically by setup script)
3. **Use HTTPS in production** - never expose the API over plain HTTP
4. **Rotate API keys regularly** - at least quarterly
5. **Monitor API usage** - check your Gemini API dashboard
6. **Enable authentication** - set API_AUTH_TOKEN in .env for production

For detailed security information, see [SECURITY.md](SECURITY.md).

