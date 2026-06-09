@echo off
cd /d "%~dp0"
set FLASK_PORT=8001
set CLIENT_PUBLIC_URL=http://localhost:8001
set SSO_PUBLIC_URL=http://localhost:8080
set SSO_INTERNAL_URL=http://localhost:8080
set FLASK_SECRET_KEY=client-secret-demo
set FLASK_DEBUG=0
echo ===== Wissen Technology Employee Portal =====
echo.
echo Starting on http://localhost:8001
echo.
py -m client.app
pause
