# RISK CHECKER — Launch Complete Application (Single Process Production Mode)
$ErrorActionPreference = "Stop"

$pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       RISK CHECKER — CYBERSECURITY AUDIT PLATFORM        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Application available at: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C in this console to terminate the server." -ForegroundColor DarkGray

Start-Process "http://127.0.0.1:5000"
& $pythonPath backend/app.py
