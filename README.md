<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

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
