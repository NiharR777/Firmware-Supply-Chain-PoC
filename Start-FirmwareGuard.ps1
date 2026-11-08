# FirmwareGuard - Start React frontend and FastAPI backend separately
$ErrorActionPreference = "Stop"

$ProjectRoot = "D:\Users\nihar\Internship\Spectra_AI\Firmware-Supply-Chain-PoC"
$FrontendDir = Join-Path $ProjectRoot "frontend\firmwareguard"
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$LogDir = Join-Path $ProjectRoot "logs"

if (-not (Test-Path $ProjectRoot)) {
    throw "Project folder not found: $ProjectRoot"
}
if (-not (Test-Path $PythonExe)) {
    throw "Virtual-environment Python not found: $PythonExe"
}
if (-not (Test-Path (Join-Path $FrontendDir "package.json"))) {
    throw "React frontend package.json not found in: $FrontendDir"
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Test-PortListening([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

# Start FastAPI only if port 8001 is not already listening.
if (Test-PortListening 8001) {
    Write-Host "Backend already listening on http://127.0.0.1:8001" -ForegroundColor Green
} else {
    $BackendCommand = "Set-Location -LiteralPath '$ProjectRoot'; & '$PythonExe' -m uvicorn src.supply_chain.api.app:app --host 127.0.0.1 --port 8001 *>> '$LogDir\backend.log'"
    Start-Process -FilePath "powershell.exe" -WindowStyle Minimized -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", $BackendCommand
    )
    Write-Host "Starting FastAPI backend on port 8001..." -ForegroundColor Cyan
}

# Start Vite only if port 3001 is not already listening.
if (Test-PortListening 3001) {
    Write-Host "Frontend already listening on http://localhost:3001" -ForegroundColor Green
} else {
    $FrontendCommand = "Set-Location -LiteralPath '$FrontendDir'; npm run dev *>> '$LogDir\frontend.log'"
    Start-Process -FilePath "powershell.exe" -WindowStyle Minimized -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", $FrontendCommand
    )
    Write-Host "Starting React frontend on port 3001..." -ForegroundColor Cyan
}

# Wait briefly for both services to bind their expected ports.
$Deadline = (Get-Date).AddSeconds(40)
do {
    Start-Sleep -Seconds 2
    $BackendReady = Test-PortListening 8001
    $FrontendReady = Test-PortListening 3001
} until (($BackendReady -and $FrontendReady) -or (Get-Date) -ge $Deadline)

Write-Host ""
if ($BackendReady) {
    Write-Host "PASS Backend:  http://127.0.0.1:8001" -ForegroundColor Green
} else {
    Write-Host "NOT READY Backend: check logs\backend.log" -ForegroundColor Red
}
if ($FrontendReady) {
    Write-Host "PASS Frontend: http://localhost:3001" -ForegroundColor Green
} else {
    Write-Host "NOT READY Frontend: check logs\frontend.log" -ForegroundColor Red
}

if ($BackendReady -and $FrontendReady) {
    Start-Process "http://localhost:3001"
    Write-Host "`nFirmwareGuard dashboard is ready." -ForegroundColor Green
} else {
    Write-Host "`nOne or more services did not start. Review the log files in: $LogDir" -ForegroundColor Yellow
}
