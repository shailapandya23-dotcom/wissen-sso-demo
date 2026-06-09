@echo off
cd /d "%~dp0"
set FLASK_PORT=8080
set FLASK_SECRET_KEY=sso-secret-demo
set FLASK_DEBUG=0
echo ===== Wissen Technology SSO Provider =====
echo.
echo Starting on http://localhost:8080
echo.
py -m sso.app
pause
