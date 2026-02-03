
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

- The Gemini API key only lives on the server (client never sees it).
- Redaction is enabled by default to avoid sending secret-like strings in code samples.
- CSP headers are enforced by the proxy server in production builds.
