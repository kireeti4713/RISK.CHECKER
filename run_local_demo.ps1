# RISK CHECKER — Launch Local Demonstration Target Server
$ErrorActionPreference = "Stop"

$pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  RISK CHECKER — Local Demonstration Lab Target Server    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Python runtime: $pythonPath" -ForegroundColor DarkGray
Write-Host "[*] Starting mock test target on http://127.0.0.1:8080 ..." -ForegroundColor Green
Write-Host "[*] Note: In RISK CHECKER Settings, ensure 'Permit Localhost Scans' is enabled." -ForegroundColor Yellow
Write-Host "[*] Press Ctrl+C to terminate." -ForegroundColor DarkGray

& $pythonPath test_server.py 8080
