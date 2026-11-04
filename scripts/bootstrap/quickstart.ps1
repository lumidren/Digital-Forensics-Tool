<#
.SYNOPSIS
  Veritas native quickstart for Windows PowerShell 5.1 / PowerShell 7. No container runtime is used.
.DESCRIPTION
  1. create .venv and install the Python package with the parity extra
  2. build the Rust binaries with the committed lockfile (cargo build --release --locked)
  3. start the API on 127.0.0.1:$Port with data in .\var
  4. run scripts\bootstrap\sample_case.py against it
  5. print the web URL
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\bootstrap\quickstart.ps1 -Full
#>
[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$WebUrl = "http://localhost:3000",
    [switch]$Full,
    [switch]$NoBuild
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"

function Test-Ready {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri "http://127.0.0.1:$Port/readyz"
        return $r.StatusCode -eq 200
    } catch {
        return $false
    }
}

Write-Host "==> [1/5] Python environment (.venv)"
if (-not (Test-Path $VenvPy)) {
    & py -3.12 -m venv (Join-Path $Root ".venv")
    if ($LASTEXITCODE -ne 0) { throw "could not create .venv (is Python 3.12 installed and 'py' on PATH?)" }
}
& $VenvPy -m pip install --upgrade pip | Out-Null
& $VenvPy -m pip install -e "python[parity]"
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Write-Host "==> [2/5] Rust binaries (cargo build --release --locked)"
if (-not $NoBuild) {
    & cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}
$env:VERITAS_BIN_DIR = Join-Path $Root "target\release"
if (-not $env:VERITAS_DATA_DIR) { $env:VERITAS_DATA_DIR = Join-Path $Root "var" }
New-Item -ItemType Directory -Force -Path $env:VERITAS_DATA_DIR | Out-Null

Write-Host "==> [3/5] API on http://127.0.0.1:$Port (data: $env:VERITAS_DATA_DIR)"
if (Test-Ready) {
    Write-Host "    an API is already answering on port $Port; reusing it"
} else {
    $log = Join-Path $env:VERITAS_DATA_DIR "api.log"
    $err = Join-Path $env:VERITAS_DATA_DIR "api.err.log"
    $proc = Start-Process -FilePath $VenvPy -ArgumentList @("-m", "uvicorn", "veritas.api.main:create_app", "--factory", "--host", "127.0.0.1", "--port", "$Port") `
        -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden -PassThru
    Set-Content -Path (Join-Path $env:VERITAS_DATA_DIR "api.pid") -Value $proc.Id -Encoding ascii
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Ready) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "API did not become ready; see $err" }
    Write-Host "    API pid $($proc.Id); logs $log, $err"
}

Write-Host "==> [4/5] sample case"
$sampleArgs = @("scripts\bootstrap\sample_case.py", "--api", "http://127.0.0.1:$Port", "--web-url", $WebUrl)
if ($Full) { $sampleArgs += "--full" }
& $VenvPy @sampleArgs
$sampleExit = $LASTEXITCODE

Write-Host "==> [5/5] web UI"
Write-Host "    start it with:  cd web; npm ci; `$env:NEXT_PUBLIC_API_BASE='http://127.0.0.1:$Port'; npm run dev"
Write-Host "    then open:      $WebUrl"
Write-Host "    sign in as 'examiner' with the password in $(Join-Path $Root 'var\bootstrap\credentials.json')"
Write-Host "    stop the API:   Stop-Process -Id (Get-Content '$(Join-Path $env:VERITAS_DATA_DIR 'api.pid')')"
exit $sampleExit
