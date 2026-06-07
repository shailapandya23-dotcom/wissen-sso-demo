@echo off
cd /d "%~dp0"
echo ===== Starting Wissen Technology SSO Demo =====
echo.
start "SSO Provider" cmd /c "set FLASK_PORT=8000 && set FLASK_SECRET_KEY=sso-secret-demo && py -m sso.app"
timeout /t 3 /nobreak >nul
start "Client Portal" cmd /c "set FLASK_PORT=8001 && set CLIENT_PUBLIC_URL=http://localhost:8001 && set SSO_PUBLIC_URL=http://localhost:8000 && set SSO_INTERNAL_URL=http://localhost:8000 && set FLASK_SECRET_KEY=client-secret-demo && py -m client.app"
echo.
echo Both servers started:
echo   SSO Provider:  http://localhost:8000
echo   Client Portal: http://localhost:8001
echo.
echo Close this window to stop both servers.
pause
