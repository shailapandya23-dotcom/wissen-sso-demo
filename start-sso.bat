@echo off
cd /d "%~dp0"
set FLASK_PORT=8000
set FLASK_SECRET_KEY=sso-secret-demo
set FLASK_DEBUG=0
echo ===== Wissen Technology SSO Provider =====
echo.
echo Starting on http://localhost:8000
echo.
py -m sso.app
pause
