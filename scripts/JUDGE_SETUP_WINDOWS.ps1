$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js >=20 is required."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm is required."
}

$majorText = node -p "process.versions.node.split('.')[0]"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$major = [int]$majorText
if ($major -lt 20) {
    throw "Node.js >=20 is required; found $(node --version)."
}

Write-Host "=== WINDOWS / NODE ==="
[System.Environment]::OSVersion.VersionString
node --version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm --version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== CLEAN INSTALL ==="
npm ci
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== LOCAL VALIDATION ==="
npm run validate:local
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== HEADLESS JUDGE VERIFY ==="
npm run judge:verify
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== WINDOWS JUDGE SETUP PASS ==="
Write-Host "Next: run npm run dev and open http://127.0.0.1:8787 to inspect the visual judge demo."
