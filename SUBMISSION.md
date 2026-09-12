# AgentFirewall — BUIDL CTC 2026 Fall

## What it is

AgentFirewall is a signing firewall for autonomous EVM agents.

The agent can propose a transaction, but it never receives the raw signer. Before signing, AgentFirewall independently requires:

1. a sender-authenticated authorization published on Sepolia;
2. an Attestcoin proof of that source transaction;
3. a verified semantic authorization recorded on Creditcoin;
4. an EIP-712 approval from a controller key different from the executor;
5. an exact match between the authorized execution and the candidate transaction.

A transaction may simulate successfully and still be blocked before `signTransaction()` if it does not match the proof-backed authorization.

## 30-second judge check

From the project root, run the launcher for the current OS:

```text
Windows:  powershell -ExecutionPolicy Bypass -File .\scripts\JUDGE_SETUP_WINDOWS.ps1
Linux:    bash ./scripts/JUDGE_SETUP_LINUX.sh
macOS:    bash ./scripts/JUDGE_SETUP_MACOS.sh
```

The decisive runtime output is:

```text
COMPROMISED : SUCCESS -> BLOCK -> signTransaction calls 0
AUTHORIZED  : SUCCESS -> ALLOW -> signTransaction calls 1
```

The mined Sepolia transaction shown in the dashboard is separate testnet reference evidence, not the transaction produced by the deterministic runtime judge harness.

For the visual proof, run `npm run dev` and open `http://127.0.0.1:8787`. The dashboard starts on the compromised candidate.

## Judge flow

```text
Sepolia AuthorizationSource
  -> Attestcoin proof
  -> Creditcoin VerifiedAuthorizationRegistry
  -> independent EIP-712 controller approval
  -> AI / MCP candidate proposal
  -> GuardedSigner
       mutated:   simulation SUCCESS -> BLOCK -> signer calls = 0
       canonical: simulation SUCCESS -> ALLOW -> signer calls = 1
  -> mined Sepolia transaction
```

The main enforcement path is `GuardedSigner.guardAndSendVerified()`.

The agent-facing integration is `src/mcp-server.ts`. MCP supplies `authorizationId`, `DeclaredIntent` and `candidateTransaction`; no MCP tool exposes or accepts the raw signer key.


## Product / ecosystem case

AgentFirewall is aimed at agent-wallet infrastructure, MCP/agent-framework maintainers, automated treasuries and DeFi automation. Its product boundary is not simulation: both an authorized and a maliciously mutated candidate may be executable. The product answers a different question immediately before signing: **does this exact transaction still match a cryptographically verified authority?**

Creditcoin is load-bearing as the cross-chain verification and authorization plane. Attestcoin proves the source authorization, `VerifiedAuthorizationRegistry` turns the proven transaction into enforceable semantics, and the eventual agent action can execute on another EVM chain. That gives Creditcoin a role in securing autonomous transaction volume beyond transactions whose final destination is Creditcoin itself.

The AI component is also load-bearing but intentionally non-authoritative: the MCP/model proposes the concrete transaction, while verified cross-chain data and deterministic policy decide whether the proposal can reach the signer.

See `WHITEPAPER.md` for the full product/security thesis and `SUBMISSION_COPY.md` for ready-to-paste form copy.

## Historical bundled on-chain evidence

The bundled on-chain evidence is a testnet reference set. The dashboard checks artifact consistency and does not treat stored state as a fresh Creditcoin verification. Current-code behavior is re-executed by `npm run judge:verify`.

### Judge E2E

Sepolia authorization:

https://sepolia.etherscan.io/tx/0xb128ed2d774c524d563d43df63349fd8ea6c39742a36a7f9a24d1d8309dab6aa

Creditcoin semantic ingest:

https://creditcoin-testnet.blockscout.com/tx/0x220f64a587451af1c425be74e644366b7784b9c26a7589cbfa412e4e69528062

GuardedSigner Sepolia execution:

https://sepolia.etherscan.io/tx/0x16096b8bd03603994630c04afe09c1c25d2382e30338058c35d2f1333eb3feb7

Observed result:

```text
mutated candidate    simulation=SUCCESS    decision=BLOCK    signerCallCount=0
canonical candidate  simulation=SUCCESS    decision=ALLOW    signerCallCount=1    mined
```

Independent authority:

```text
controller  0x4b79bD0B1Be2d9a68E5355e637fb74b84619D2F6
executor    0x82Bb49277DD5d45A194Ea21ab36fcf2aA56B9A18
separated   true
```

### Real MCP live path

A separate one-shot authorization exercised the actual MCP stdio tool path.

Sepolia authorization:

https://sepolia.etherscan.io/tx/0xb9c5730fbe8ea8ac78f32df3313998f5c81936263120a6d7a2ff98725959a183

Creditcoin semantic ingest:

https://creditcoin-testnet.blockscout.com/tx/0x73f80ac837634e724c17f4f1df9c6faeb82996ce6588a2f665f4ad4340765be5

MCP GuardedSigner execution:

https://sepolia.etherscan.io/tx/0xead4f51d00e69bfb5e63a9313333d100bb0edb50c68bf9ab8e27e6a48c9153cf

The live client negotiated MCP protocol `2025-06-18` and invoked `agentfirewall_execute` through stdio:

```text
mutated candidate    BLOCK    signerCallCount=0
canonical candidate  ALLOW    signerCallCount=1    mined
```

The MCP run used the same independent controller/executor trust split. The model never received the executor private key or raw signer.

## Reproduce the judge flow

The archive intentionally excludes `node_modules/`. With Node.js 20+ installed, use the OS launcher for a clean `npm ci`, the full local validation gate, and the headless judge assertions:

```text
Windows:  powershell -ExecutionPolicy Bypass -File .\scripts\JUDGE_SETUP_WINDOWS.ps1
Linux:    bash ./scripts/JUDGE_SETUP_LINUX.sh
macOS:    bash ./scripts/JUDGE_SETUP_MACOS.sh
```

No Git checkout, public repository, admin/root access, RPC credentials, or wallet keys are required for the runtime judge path or local testnet artifact-consistency check. The equivalent manual commands are:

```bash
npm ci
npm run validate:local
npm run judge:verify
npm run dev
```

Fresh testnet E2E:

```bash
npm run live:e2e
```

`npm run live:e2e` requires trusted Sepolia/Creditcoin RPC endpoints, a disposable funded executor key, a different controller key, and explicit fee ceilings. It does not require Git metadata: source provenance is recorded as a clean Git commit when available, otherwise as a deterministic SHA-256 runtime-source fingerprint.

The resulting `build/live-evidence.json` records:

- Sepolia authorization transaction;
- Creditcoin semantic-ingest transaction;
- controller/executor separation;
- mutated `simulation=SUCCESS`, `BLOCK`, `signerCallCount=0`;
- canonical `simulation=SUCCESS`, `ALLOW`, `signerCallCount=1`;
- mined Sepolia GuardedSigner execution.

Private keys are not written into the evidence artifact.

## MCP adapter

Run:

```bash
npm run mcp
```

The stdio server uses `@modelcontextprotocol/server` 2.0.0 and exposes:

- `agentfirewall_check` — verified ALLOW/BLOCK without signing;
- `agentfirewall_execute` — optional Sepolia-only guarded execution when `AGENTFIREWALL_MCP_ENABLE_SEND=true`.

The executor key and controller approval remain process-local.

## Hackathon additions

- Sepolia `AuthorizationSource`;
- Attestcoin proof ingestion into Creditcoin;
- semantic `VerifiedAuthorizationRegistry`;
- execution commitments bound to nonce, expiry and runtime code identity;
- `GuardedSigner` with canonical envelope, fee ceilings and raw-transaction reparse;
- separate EIP-712 controller authority;
- current-flow E2E orchestration and compact judge evidence;
- agent-facing MCP stdio adapter;
- judge UI centered on authorization -> attestation -> controller -> agent -> signer.

## Scope

This is testnet/reference code, not production custody software.

Current limits:

- one configured RPC is trusted for each verified read path;
- no explicit authorization revocation/epoch yet;
- proxy detection covers common layouts, not every custom proxy.

See `ARCHITECTURE.md`, `THREAT_MODEL.md`, `VALIDATION.md` and `DEMO_SCRIPT.md` for implementation and security detail.


## Originality and build provenance

AgentFirewall development started on September 7, 2026. The initial snapshot contained the analyzer, policy checks, RPC inspection, dashboard, SDK guard and mock-wallet demo. The Attestcoin-backed authorization flow, Creditcoin registry integration, independent controller approval, live E2E path, MCP integration and hardened signer boundary were added in the current build. See `PROJECT_BASELINE.txt`.

The repository makes no production-user, revenue, audit or custody-safety claim. Public repository: https://github.com/itisfloris/AgentFirewall.
