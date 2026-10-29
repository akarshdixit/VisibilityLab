# Launch VisibilityLab locally: API, worker and frontend, each in its own PowerShell window.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
$root = Split-Path -Parent $PSScriptRoot
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root'; python -m webapp.backend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root'; python -m webapp.backend.worker"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\webapp\frontend'; npm run dev"
Write-Host "API      http://127.0.0.1:8000/docs"
Write-Host "Frontend http://127.0.0.1:3000  (first start compiles for ~10 s)"
