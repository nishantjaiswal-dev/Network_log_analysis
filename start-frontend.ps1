# Start the forensic dashboard frontend on Windows
#
#   powershell -ExecutionPolicy Bypass -File .\start-frontend.ps1

$ErrorActionPreference = 'Stop'
$frontend = Join-Path $PSScriptRoot 'frontend'

if (-not (Test-Path (Join-Path $frontend 'node_modules'))) {
    Write-Host 'Installing frontend dependencies (npm install)...'
    Set-Location $frontend
    npm install
}

Set-Location $frontend
Write-Host 'Starting frontend dev server at http://127.0.0.1:5173  (Ctrl+C to stop)'
npm run dev
