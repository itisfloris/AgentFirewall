[CmdletBinding()]
param(
    [string]$ProjectPath = ".",
    [switch]$BroadcastExactExecution
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

$scriptOwnedEnvironment = @("AUTHORIZATION_SOURCE_ADDRESS", "AGENTFIREWALL_REGISTRY_ADDRESS", "SOURCE_CHAIN_KEY", "SOURCE_CHAIN_ID", "AGENTFIREWALL_DEMO_VALIDITY_SECONDS", "AGENTFIREWALL_LIVE_SEND")
$environmentSnapshot = Save-Environment $scriptOwnedEnvironment

try {
$deploymentPath = Join-Path (Get-Location) "build\live-deployment.json"
if (-not (Test-Path $deploymentPath)) {
    throw "Missing $deploymentPath. Deploy the B3 stack first."
}

$deployment = Get-Content $deploymentPath -Raw | ConvertFrom-Json

if ($deployment.version -ne "AgentFirewall.LiveDeployment.v1") {
    throw "Unsupported deployment artifact version: $($deployment.version)"
}

if (-not $deployment.source.address -or -not $deployment.semanticRegistry.address -or -not $deployment.semanticRegistry.sourceChainKey) {
    throw "Deployment artifact is incomplete: source + semantic registry + sourceChainKey are required."
}

if (-not $env:AGENTFIREWALL_TESTNET_PRIVATE_KEY) {
    throw "AGENTFIREWALL_TESTNET_PRIVATE_KEY is required for publish/ingest. It is not persisted by this script."
}

if ($BroadcastExactExecution -and -not $env:AGENTFIREWALL_CONTROLLER_PRIVATE_KEY) {
    throw "AGENTFIREWALL_CONTROLLER_PRIVATE_KEY is required for the guarded broadcast and must differ from the executor key."
}

$env:AUTHORIZATION_SOURCE_ADDRESS = [string]$deployment.source.address
$env:AGENTFIREWALL_REGISTRY_ADDRESS = [string]$deployment.semanticRegistry.address
$env:SOURCE_CHAIN_KEY = [string]$deployment.semanticRegistry.sourceChainKey
$env:SOURCE_CHAIN_ID = "11155111"

if (-not $env:AGENTFIREWALL_DEMO_VALIDITY_SECONDS) {
    $env:AGENTFIREWALL_DEMO_VALIDITY_SECONDS = "7200"
}

$env:AGENTFIREWALL_LIVE_SEND = if ($BroadcastExactExecution) { "true" } else { "false" }

Write-Host "`n=== AgentFirewall BUIDL live semantic round-trip ===" -ForegroundColor Yellow
Write-Host "AuthorizationSource: $env:AUTHORIZATION_SOURCE_ADDRESS"
Write-Host "Registry: $env:AGENTFIREWALL_REGISTRY_ADDRESS"
Write-Host "Source chain key: $env:SOURCE_CHAIN_KEY"
Write-Host "Exact execution broadcast: $env:AGENTFIREWALL_LIVE_SEND"

Run-Native "1/6 Pre-flight submission doctor" {
    npm run submission:doctor
}

Run-Native "2/6 Publish Authorization.v3 on Sepolia" {
    npm run attestcoin:publish-demo-authorization
}

Run-Native "3/6 Generate Attestcoin proof and semantic-ingest on CC3" {
    npm run attestcoin:ingest-authorization
}

if ($env:AGENTFIREWALL_CONTROLLER_PRIVATE_KEY) {
    Run-Native "4/6 Create independent controller EIP-712 approval" {
        npm run controller:approve-live
    }
}
elseif ($BroadcastExactExecution) {
    throw "Controller approval is required for broadcast."
}
else {
    Write-Host "4/6 Controller approval skipped for dry-run only." -ForegroundColor Yellow
}

Run-Native "5/6 Prove mutated BLOCK / exact ALLOW via current GuardedSigner path" {
    npm run demo:verified-live
}

Run-Native "6/6 Validate judge evidence bundle" {
    npm run live:evidence
}

$evidencePath = Join-Path (Get-Location) "build\live-evidence.json"
if (-not (Test-Path $evidencePath)) {
    throw "Expected judge evidence file was not produced: $evidencePath"
}

$evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json

if ($evidence.firewall.mutatedExecutablePayload.simulation -ne "SUCCESS" -or
    $evidence.firewall.mutatedExecutablePayload.decision -ne "BLOCK" -or
    $evidence.firewall.exactProofBackedPayload.simulation -ne "SUCCESS" -or
    $evidence.firewall.exactProofBackedPayload.decision -ne "ALLOW") {
    throw "Judge evidence does not contain the required executable-mutated BLOCK / exact-proof-backed ALLOW pair."
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " LIVE SEMANTIC ROUND-TRIP PASSED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Sepolia authorization: $($evidence.source.explorerTransaction)"
Write-Host "Creditcoin semantic ingest: $($evidence.creditcoin.explorerTransaction)"
Write-Host "Creditcoin registry: $($evidence.creditcoin.explorerContract)"
if ($evidence.execution) {
    Write-Host "Exact Sepolia execution: $($evidence.execution.explorerTransaction)"
}
Write-Host "Evidence: $evidencePath"

}
finally {
    Restore-Environment $environmentSnapshot
    Pop-Location
}
