# start_windows.ps1 — Start the AWS Video Dashboard on Windows
# Run: powershell -ExecutionPolicy Bypass -File start_windows.ps1

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$pythonPath = Join-Path $root "venv\Scripts\python.exe"
$waitress = Join-Path $root "venv\Scripts\waitress-serve.exe"
$dataDir = Join-Path $root "data"

# Check venv exists
if (-not (Test-Path $pythonPath)) {
    Write-Host "[ERROR] Virtual environment not found. Run install_windows.ps1 first." -ForegroundColor Red
    exit 1
}

# Load .env
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^([^#=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

# Set required env vars
$env:DATA_DIR = $dataDir
if (-not $env:FLASK_SECRET_KEY) {
    Write-Host "[ERROR] FLASK_SECRET_KEY not set. Run install_windows.ps1 or set it in .env" -ForegroundColor Red
    exit 1
}

# Create data dir if missing
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
}

Write-Host ""
Write-Host "=== AWS Video Dashboard ===" -ForegroundColor Cyan
Write-Host "Data directory: $dataDir" -ForegroundColor Gray
Write-Host ""

# Start with waitress (production) or fallback to Flask dev server
if (Test-Path $waitress) {
    Write-Host "Starting with Waitress on http://localhost:5000 ..." -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
    Write-Host ""
    & $waitress --host=0.0.0.0 --port=5000 --threads=4 "app:app"
} else {
    Write-Host "Starting with Flask dev server on http://localhost:5000 ..." -ForegroundColor Green
    Write-Host "(Install waitress for production use: pip install waitress)" -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
    Write-Host ""
    & $pythonPath app.py
}
