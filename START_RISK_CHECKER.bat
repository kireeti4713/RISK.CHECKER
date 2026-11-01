@echo off
title RISK CHECKER Platform
cd /d "%~dp0"
echo ========================================================
echo   Starting RISK CHECKER Cyber Risk Assessment Platform
echo ========================================================
echo [1] Local PC Access:           http://127.0.0.1:5000
echo [2] Phone / Same Wi-Fi Access: http://192.168.1.7:5000
echo ========================================================
timeout /t 2 >nul
start http://127.0.0.1:5000
echo Running production server... (Keep this window open)
echo Press Ctrl+C to stop.
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" backend\app.py
if %ERRORLEVEL% NEQ 0 (
    python backend\app.py
)
pause
