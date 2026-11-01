# RISK CHECKER — Launch Backend REST API Server
$ErrorActionPreference = "Stop"

$pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  RISK CHECKER — Backend REST API Server (Flask + SQLite) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Python runtime: $pythonPath" -ForegroundColor DarkGray
Write-Host "[*] Starting Flask server on http://127.0.0.1:5000 ..." -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to terminate." -ForegroundColor DarkGray

& $pythonPath backend/app.py
