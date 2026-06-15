#Requires -Version 5.1
<#
.SYNOPSIS
  Aegis OSINT Framework — Windows installer / updater.

.DESCRIPTION
  One-line install:
    powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/scripts/install.ps1 | iex"

  Or with curl (PowerShell 7+):
    irm https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/scripts/install.ps1 | iex

.NOTES
  - Clones into %USERPROFILE%\Aegis-OSINT-AI by default (override with $env:AEGIS_DIR).
  - Requires: git, Python 3.12+, Node.js 18+.
  - Sets up .venv, installs backend runtime deps, runs Alembic migrations.
  - Brings up Docker Compose stack if docker is available.
#>

$ErrorActionPreference = "Stop"

$repoUrl = if ($env:AEGIS_REPO_URL) { $env:AEGIS_REPO_URL } else { "https://github.com/steelai-bot/Aegis-OSINT-AI.git" }
$branch  = if ($env:AEGIS_BRANCH)   { $env:AEGIS_BRANCH }   else { "main" }
$targetDir = if ($env:AEGIS_DIR)     { $env:AEGIS_DIR }      else { Join-Path $env:USERPROFILE "Aegis-OSINT-AI" }

function Test-Cmd($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Require-Cmd($name) {
    if (-not (Test-Cmd $name)) {
        Write-Host "[aegis] ERROR: '$name' is required but not found." -ForegroundColor Red
        Write-Host "       Please install it and try again." -ForegroundColor Red
        exit 1
    }
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Aegis OSINT — Windows Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Require-Cmd "git"

# ── Step 1: Clone or update ────────────────────────────────────────────────

$isAegis = Test-Path (Join-Path $targetDir ".git")
if (-not $isAegis) {
    Write-Host "[aegis] Cloning $repoUrl ..." -ForegroundColor Green
    git clone --branch $branch $repoUrl $targetDir
} else {
    Write-Host "[aegis] Existing clone found at $targetDir" -ForegroundColor Green
}

Set-Location $targetDir
git fetch --prune origin 2>$null | Out-Null
git pull --ff-only origin $branch 2>$null | Out-Null

Write-Host "[aegis] Repository is up to date: $(git rev-parse --short HEAD)" -ForegroundColor Green
Write-Host ""

# ── Step 2: Python virtual environment + deps ──────────────────────────────

Write-Host "[aegis] Setting up Python virtual environment ..." -ForegroundColor Green

$pythonCmd = $null
foreach ($name in @("python", "python3", "py")) {
    if (Test-Cmd $name) {
        $pythonCmd = $name
        break
    }
}
if (-not $pythonCmd) {
    Write-Host "[aegis] WARNING: Python not found — skipping backend setup." -ForegroundColor Yellow
} else {
    $venvPath = Join-Path $targetDir ".venv"
    $venvPython = Join-Path $venvPath "Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        & $pythonCmd -m venv $venvPath
    }

    & $venvPython -m pip install --upgrade pip --quiet 2>$null | Out-Null
    & $venvPython -m pip install -r backend\requirements.runtime.txt --quiet 2>$null | Out-Null

    Write-Host "[aegis] Backend dependencies installed." -ForegroundColor Green

    # Run Alembic migrations if DATABASE_URL is set
    if ($env:DATABASE_URL -or $env:AEGIS_DATABASE_URL) {
        Write-Host "[aegis] Running Alembic migrations ..." -ForegroundColor Green
        & $venvPython -m alembic upgrade head
        Write-Host "[aegis] Migrations complete." -ForegroundColor Green
    } else {
        Write-Host "[aegis] Skipping migrations (no DATABASE_URL set)." -ForegroundColor Yellow
    }
}

# ── Step 3: Frontend dependencies ──────────────────────────────────────────

Write-Host ""
Write-Host "[aegis] Setting up frontend ..." -ForegroundColor Green

if (Test-Cmd "node") {
    Push-Location "$targetDir\frontend"
    if (-not (Test-Path "node_modules")) {
        npm install 2>$null | Out-Null
    } else {
        npm install 2>$null | Out-Null
    }
    Pop-Location
    Write-Host "[aegis] Frontend dependencies installed." -ForegroundColor Green
} else {
    Write-Host "[aegis] WARNING: Node.js not found — skipping frontend setup." -ForegroundColor Yellow
}

# ── Step 4: Docker Compose (optional) ──────────────────────────────────────

Write-Host ""
if (Test-Cmd "docker") {
    $composeFile = Join-Path $targetDir "docker-compose.yml"
    if (Test-Path $composeFile) {
        Write-Host "[aegis] Starting Docker Compose stack ..." -ForegroundColor Green
        docker compose up -d 2>$null | Out-Null
        Write-Host "[aegis] Docker stack running (pgvector + API)." -ForegroundColor Green
    }
} else {
    Write-Host "[aegis] Docker not found — skipping container setup." -ForegroundColor Yellow
}

# ── Step 5: Create .env template if missing ────────────────────────────────

$envFile = Join-Path $targetDir ".env"
if (-not (Test-Path $envFile)) {
    $template = @"
# Aegis v2 Configuration
AEGIS_ENVIRONMENT=development
AEGIS_DEBUG=false
AEGIS_AUTH_ENABLED=false
AEGIS_DATABASE_URL=postgresql+asyncpg://aegis:aegis@localhost:5432/aegis
AEGIS_REDIS_URL=redis://localhost:6379/0
AEGIS_JWT_SECRET=change-me-in-production
# AEGIS_SHODAN_API_KEY=
# AEGIS_VIRUSTOTAL_API_KEY=
# AEGIS_HIBP_API_KEY=
"@
    Set-Content -Path $envFile -Value $template
    Write-Host "[aegis] Created .env template — edit it with your API keys." -ForegroundColor Green
}

# ── Done ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Aegis OSINT installed successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install dir: $targetDir"
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    cd $targetDir"
Write-Host "    .venv\Scripts\activate"
Write-Host "    uvicorn backend.api.app:create_app --factory --reload"
Write-Host ""