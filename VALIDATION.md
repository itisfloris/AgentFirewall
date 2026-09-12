# Validation

## Local gate

Requires Node.js 20+. `node_modules/` is not part of the submission archive.

Cross-platform launchers perform a clean `npm ci`, run `npm run validate:local`, then execute the current GuardedSigner through the runtime judge verifier:

```text
Windows:  powershell -ExecutionPolicy Bypass -File .\scripts\JUDGE_SETUP_WINDOWS.ps1
Linux:    bash ./scripts/JUDGE_SETUP_LINUX.sh
macOS:    bash ./scripts/JUDGE_SETUP_MACOS.sh
```

Manual equivalent:

```bash
npm ci
npm run supply-chain:check
npm run typecheck
npm test
npm run live:evidence:local
npm run judge:verify
```

`npm run judge:verify` requires no RPC or wallet secrets; it executes the current `GuardedSigner.guardAndSendVerified()` implementation with instrumented local provider/signer infrastructure and asserts the runtime BLOCK/0 + ALLOW/1 pair. It does not read the dashboard API or bundled live evidence. `npm audit --audit-level=high` is optional because it needs registry access.

The TypeScript tests cover the signer path, nonce reservation, controller split and fee binding, chain snapshots, optional secondary RPC disagreement, proof/registry parsing and evidence consistency. They are not a replacement for Solidity/EVM fuzzing or formal verification.

## Cross-platform check status

The clean-install judge path has been exercised on Windows, native macOS, and Ubuntu userland under WSL1. The Linux launcher is a normal Bash/Node path and does not depend on WSL-specific commands.

## Fresh RC6 live E2E

Required environment groups:

- `SEPOLIA_RPC_URL`, `CREDITCOIN_RPC_URL`;
- `AGENTFIREWALL_TESTNET_PRIVATE_KEY` — disposable executor/testnet key;
- `AGENTFIREWALL_CONTROLLER_PRIVATE_KEY` — **different** disposable controller key;
- the four `AGENTFIREWALL_MAX_*` fee ceilings;
- deployment/trust anchors from `.env.example` or `build/live-deployment.json`.

Then run:

```bash
npm run live:e2e
```

Git is optional for this fresh run. With Git metadata, provenance is the clean commit. In a standalone archive, provenance is a deterministic SHA-256 fingerprint over the runtime source bundle.

Success requires all of the following in `build/live-evidence.json`:

```text
build.sourceId or legacy build.sourceCommit = present
build.sourceTreeClean                       = true only when sourceKind = git
controllerApproval.authoritySeparated       = true
firewall.mutatedExecutablePayload          = SUCCESS / BLOCK
guardedSigner.mutated.signerCallCount      = 0
firewall.exactProofBackedPayload            = SUCCESS / ALLOW
guardedSigner.canonical.signerCallCount    = 1
transactions.sourceAuthorization            = fresh Sepolia tx
transactions.creditcoinIngest               = fresh Creditcoin tx
transactions.execution               = fresh mined Sepolia tx
```

## MCP adapter

Start the stdio server with:

```bash
npm run mcp
```

`agentfirewall_check` never signs. `agentfirewall_execute` remains disabled unless `AGENTFIREWALL_MCP_ENABLE_SEND=true`, and the execution adapter is intentionally Sepolia-only.

## Check bundled live evidence against live RPCs

PowerShell:

```powershell
$env:SEPOLIA_RPC_URL = "<trusted Sepolia RPC>"
$env:CREDITCOIN_RPC_URL = "<trusted Creditcoin CC3 RPC>"
npm run live:evidence
```

The recorded authorization is intentionally one-shot. After the canonical execution is mined, its execution nonce is spent, so `authorizationCurrentlyUsable=false` is expected. This command re-verifies the recorded Sepolia receipts and Creditcoin registry provenance; it does not make the authorization reusable.

## Compile contracts

```bash
npm run contracts:compile
```

The Solidity target is `0.8.28`. `contracts:compile` performs no package acquisition and requires exact local `solc@0.8.28` plus `@gluwa/asc-contracts@0.2.1`. These optional compiler dependencies are outside the application lockfile, so full rebuild hermeticity is not claimed. The mandatory judge path uses `npm run contracts:security`.

There is currently no completed Foundry/Hardhat fuzz suite, Solidity coverage report, Solhint/Slither report or formal verification.

## Dashboard

```bash
npm run dev
```

Open `http://127.0.0.1:8787`. `/api/judge-demo` serves bundled testnet reference evidence used by the five-stage UI and reports local artifact consistency separately from live registry verification. This dashboard path does not require `.git` metadata or a public repository.

Testnet scripts should only be used with disposable test keys. They do not clear secrets already exported in a parent shell.
