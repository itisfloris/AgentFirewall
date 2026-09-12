[CmdletBinding()]
param(
    [string]$ProjectPath = "."
)

$ErrorActionPreference = "Stop"
Push-Location $ProjectPath

function Run-Native {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [scriptblock]$Command
    )

    Write-Host "`n========================================" -ForegroundColor DarkGray
    Write-Host " $Name" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkGray

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Name FAILED with exit code $LASTEXITCODE"
    }

    Write-Host "$Name PASSED" -ForegroundColor Green
}

function Save-Environment {
    param([string[]]$Names)
    $snapshot = @{}
    foreach ($name in $Names) {
        $snapshot[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    return $snapshot
}

function Restore-Environment {
    param([hashtable]$Snapshot)
    foreach ($name in $Snapshot.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Snapshot[$name], "Process")
    }
}

$scriptOwnedEnvironment = @("SOURCE_CHAIN_ID", "B2_DEPLOY_TARGET", "AUTHORIZATION_SOURCE_ADDRESS")
$environmentSnapshot = Save-Environment $scriptOwnedEnvironment

try {
if (-not $env:AGENTFIREWALL_TESTNET_PRIVATE_KEY) {
    throw "AGENTFIREWALL_TESTNET_PRIVATE_KEY is required in this PowerShell process. It is never written to build/live-deployment.json."
}

if (-not $env:SOURCE_CHAIN_KEY -or $env:SOURCE_CHAIN_KEY -notmatch '^\d+$') {
    throw "SOURCE_CHAIN_KEY must be set to the current Creditcoin chain key registered for Sepolia. Do not guess it."
}

$env:SOURCE_CHAIN_ID = "11155111"

Write-Host "`n=== AgentFirewall B3 deterministic deployment ===" -ForegroundColor Yellow
Write-Host "Project: $(Get-Location)"
Write-Host "Source chain id: $env:SOURCE_CHAIN_ID"
Write-Host "Source chain key: $env:SOURCE_CHAIN_KEY"

Run-Native "1/4 Compile Solidity + ASC using exact local optional toolchain" {
    npm run contracts:compile
}

Run-Native "2/4 TypeScript typecheck" {
    npm run typecheck
}

$env:B2_DEPLOY_TARGET = "source"
Run-Native "3/4 Deploy AuthorizationSource on Sepolia" {
    npm run b3:deploy
}

$deploymentPath = Join-Path (Get-Location) "build\live-deployment.json"
if (-not (Test-Path $deploymentPath)) {
    throw "Deployment artifact was not created at $deploymentPath"
}

$deployment = Get-Content $deploymentPath -Raw | ConvertFrom-Json
if (-not $deployment.source.address) {
    throw "Deployment artifact has no source.address"
}

$env:AUTHORIZATION_SOURCE_ADDRESS = [string]$deployment.source.address
$env:B2_DEPLOY_TARGET = "semantic-registry"

Run-Native "4/4 Deploy VerifiedAuthorizationRegistry on Creditcoin CC3" {
    npm run b3:deploy
}

$deployment = Get-Content $deploymentPath -Raw | ConvertFrom-Json

if (-not $deployment.semanticRegistry.address) {
    throw "Deployment artifact has no semanticRegistry.address"
}

if ([string]$deployment.semanticRegistry.trustedAuthorizationSource -ne [string]$deployment.source.address) {
    throw "Recorded registry trusted source does not match the recorded AuthorizationSource"
}

Write-Host "`n=== B3 STACK DEPLOYED ===" -ForegroundColor Green
Write-Host "AuthorizationSource: $($deployment.source.address)"
Write-Host "VerifiedAuthorizationRegistry: $($deployment.semanticRegistry.address)"
Write-Host "Deployment artifact: $deploymentPath"
Write-Host "No private key is stored in the deployment artifact." -ForegroundColor Green

}
finally {
    Restore-Environment $environmentSnapshot
    Pop-Location
}
