# install_windows.ps1 — AWS Video Dashboard installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== AWS Video Dashboard — Windows Installer ===" -ForegroundColor Cyan
Write-Host ""

# --- Check Python ---
$py = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.(1[0-9]|[2-9][0-9])") {
            $py = $cmd
            Write-Host "[OK] Found $ver" -ForegroundColor Green
            break
        }
    } catch {}
}
if (-not $py) {
    Write-Host "[ERROR] Python 3.10+ is required. Download from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "        Make sure to check 'Add python.exe to PATH' during install." -ForegroundColor Yellow
    exit 1
}

# --- Create virtual environment ---
$venvPath = Join-Path $PSScriptRoot "venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "[...] Creating virtual environment..." -ForegroundColor Yellow
    & $py -m venv $venvPath
    Write-Host "[OK] Virtual environment created" -ForegroundColor Green
} else {
    Write-Host "[OK] Virtual environment already exists" -ForegroundColor Green
}

# --- Activate and install dependencies ---
$pipPath = Join-Path $venvPath "Scripts\pip.exe"
$pythonPath = Join-Path $venvPath "Scripts\python.exe"

Write-Host "[...] Installing dependencies..." -ForegroundColor Yellow
& $pipPath install --upgrade pip --quiet 2>&1 | Out-Null
& $pipPath install -r (Join-Path $PSScriptRoot "requirements.txt") --quiet 2>&1 | Out-Null
# Install waitress (Windows-compatible WSGI server, replaces gunicorn)
& $pipPath install "waitress>=3.0,<4.0" --quiet 2>&1 | Out-Null
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

# --- Create data directory ---
$dataDir = Join-Path $PSScriptRoot "data"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
    Write-Host "[OK] Data directory created: $dataDir" -ForegroundColor Green
} else {
    Write-Host "[OK] Data directory exists: $dataDir" -ForegroundColor Green
}

# --- Generate secret key if not set ---
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    $secret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
    Set-Content -Path $envFile -Value "FLASK_SECRET_KEY=$secret"
    Write-Host "[OK] Generated secret key in .env" -ForegroundColor Green
} else {
    Write-Host "[OK] .env file already exists" -ForegroundColor Green
}

# --- Run tests to verify installation ---
Write-Host ""
Write-Host "[...] Running quick verification..." -ForegroundColor Yellow
$testResult = & $pythonPath -m pytest tests/ -q --tb=line 2>&1
$lastLine = ($testResult | Select-Object -Last 1)
if ($lastLine -match "passed") {
    Write-Host "[OK] $lastLine" -ForegroundColor Green
} else {
    Write-Host "[WARN] Some tests may have failed — check output above" -ForegroundColor Yellow
    $testResult | ForEach-Object { Write-Host $_ }
}

# --- Done ---
Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the dashboard:" -ForegroundColor White
Write-Host "  .\start_windows.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "Or manually:" -ForegroundColor White
Write-Host "  .\venv\Scripts\activate" -ForegroundColor Yellow
Write-Host "  python app.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "Then open: http://localhost:5000" -ForegroundColor Cyan
Write-Host ""
