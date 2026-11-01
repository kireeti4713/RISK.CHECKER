@echo off
title RISK CHECKER — Public Internet Sharing
cd /d "%~dp0"
echo =======================================================================
echo          RISK CHECKER — PUBLIC INTERNET SHARE (CLOUDFLARE)
echo =======================================================================
echo.
echo Starting backend server if not already running...
start /b "" "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" backend\app.py
timeout /t 2 >nul
echo.
echo Creating secure global HTTPS tunnel via Cloudflare...
echo Look for the public link ending with .trycloudflare.com below!
echo Anyone anywhere in the world on phone or PC can open that link.
echo.
echo -----------------------------------------------------------------------
"C:\Users\kiree\AppData\Local\Microsoft\WinGet\Packages\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe" tunnel --url http://127.0.0.1:5000
pause
