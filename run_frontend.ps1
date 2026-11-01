# RISK CHECKER — Launch Vite React Dev Server
$ErrorActionPreference = "Stop"

$nodePath = "C:\Users\kiree\AppData\Local\Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_Microsoft.Winget.Source_8wekyb3d8bbwe\node-v24.20.0-win-x64"
if (Test-Path $nodePath) {
    $env:PATH = "$nodePath;" + $env:PATH
}

Set-Location "$PSScriptRoot\frontend"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  RISK CHECKER — Frontend Development Server (Vite + React)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Starting Vite dev server on http://127.0.0.1:5173 ..." -ForegroundColor Green
Write-Host "[*] Proxying API calls to backend at http://127.0.0.1:5000" -ForegroundColor DarkGray

npm run dev
