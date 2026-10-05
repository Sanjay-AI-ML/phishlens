@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo PhishLens needs Node.js 22.12 or newer installed on this computer.
  pause
  exit /b 1
)
if not exist "dist-server\server.mjs" (
  echo Build the app first with: npm ci then npm run build
  pause
  exit /b 1
)
echo Open http://127.0.0.1:4173 in your browser.
echo Keep this window open. Press Ctrl+C to stop PhishLens.
node "dist-server\server.mjs"
if errorlevel 1 pause
