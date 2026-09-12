# AgentFirewall

AgentFirewall is a proof-backed execution firewall for autonomous EVM transaction systems. Transaction proposal and signing authority are separated: source-chain authorization is proven through Attestcoin, recorded on Creditcoin, independently controller-approved, and enforced immediately before signing by `GuardedSigner.guardAndSendVerified()`.

## Why it exists

A transaction can simulate successfully and still be unauthorized. Simulation proves executability, not authority.

AgentFirewall binds the signer to the exact authorized execution envelope: recipient, target, calldata, value, nonce, runtime code identity, chain and fee limits. A mutated candidate is blocked before `signTransaction()`.

**Target users:** agent-wallet infrastructure, MCP/framework maintainers, automated treasuries, DeFi automation and applications that let autonomous software prepare EVM transactions without owning custody.

**Creditcoin:** Attestcoin proves the source transaction; `VerifiedAuthorizationRegistry` converts the proof into authorization semantics consumed by the signing boundary. Execution may remain on another EVM chain while Creditcoin provides the verification plane.

**AI track:** the agent is the untrusted transaction proposer; AgentFirewall is the cryptographic authorization boundary between the agent and the signer. Cryptographically verified cross-chain data determines whether the proposal may reach the signer and trigger an on-chain action.

**Concrete attack story:** an autonomous agent prepares a valid-looking transfer that simulates successfully, but a compromised planner/tool mutates an execution-critical field. AgentFirewall detects that the concrete candidate no longer matches the verified authority and blocks it before the private key is used.

## Judge check

```text
COMPROMISED
simulation SUCCESS
AgentFirewall BLOCK
signTransaction calls 0

AUTHORIZED
simulation SUCCESS
AgentFirewall ALLOW
signTransaction calls 1
```

Node.js 20+:

```text
Windows: powershell -ExecutionPolicy Bypass -File .\scripts\JUDGE_SETUP_WINDOWS.ps1
Linux:   bash ./scripts/JUDGE_SETUP_LINUX.sh
macOS:   bash ./scripts/JUDGE_SETUP_MACOS.sh
```

A passing run ends with:

```text
=== JUDGE VERIFY PASS ===
```

`npm run judge:verify` executes the current `GuardedSigner` implementation with instrumented provider/signer boundaries. The executable mutation must produce `BLOCK / signerCalls=0`; the canonical candidate must produce `ALLOW / signerCalls=1`.

## Security path

```text
Sepolia AuthorizationSource
  -> Attestcoin proof
  -> Creditcoin VerifiedAuthorizationRegistry
  -> independent EIP-712 controller approval v2
  -> candidate transaction
  -> GuardedSigner
  -> signer
```

Verified authorization is necessary but not sufficient. Local hard policy and analyzer deny rules remain independent deny layers.

`GuardedSigner` reserves sender/chain/nonce before asynchronous preflight, freezes the execution-critical envelope, verifies controller approval and proof-backed authorization, rechecks chain/nonce/expiry/runtime code at the signing boundary, signs, parses the returned raw transaction, rejects any mismatch, then broadcasts the exact signed bytes.

A `BLOCK` occurs before signing.

## Validation

```bash
npm ci
npm run validate:local
npm run judge:verify
```

`validate:local` checks the lockfile supply chain, Solidity source/artifact invariants, TypeScript, tests and bundled testnet-evidence consistency. The mandatory path performs no runtime package acquisition.

`contracts:compile` is an optional source rebuild requiring exact local `solc@0.8.28` and `@gluwa/asc-contracts@0.2.1`. It is not part of the judge/runtime gate.

## Fresh live E2E

With disposable testnet executor/controller keys and configured Sepolia/Creditcoin RPC endpoints:

```bash
npm run live:e2e
```

Flow:

```text
Sepolia authorization
  -> Attestcoin/Creditcoin semantic ingest
  -> controller EIP-712 approval
  -> executable mutation: BLOCK / signerCalls=0
  -> canonical execution: ALLOW / signerCalls=1
  -> mined Sepolia transaction
  -> build/live-evidence.json
```

Fresh evidence records transaction hashes, controller/executor separation, signer-call evidence and source provenance. Private keys are never written to the evidence artifact. Configuration is documented in `.env.example`.

## Testnet reference evidence

The repository includes a verified testnet reference set for the same proof-backed authorization and GuardedSigner enforcement path. It is retained as on-chain provenance and regression evidence; current-code behavior is always re-executed by `npm run judge:verify` rather than inferred from stored JSON.

| Stage | Transaction |
|---|---|
| Sepolia authorization | `0xb128ed2d774c524d563d43df63349fd8ea6c39742a36a7f9a24d1d8309dab6aa` |
| Creditcoin semantic ingest | `0x220f64a587451af1c425be74e644366b7784b9c26a7589cbfa412e4e69528062` |
| Guarded Sepolia execution | `0x16096b8bd03603994630c04afe09c1c25d2382e30338058c35d2f1333eb3feb7` |

```text
mutated candidate    simulation=SUCCESS    decision=BLOCK    signerCallCount=0
canonical candidate  simulation=SUCCESS    decision=ALLOW    signerCallCount=1    mined
```

Controller and executor are independent:

```text
controller  0x4b79bD0B1Be2d9a68E5355e637fb74b84619D2F6
executor    0x82Bb49277DD5d45A194Ea21ab36fcf2aA56B9A18
```

Explorer links:

- Sepolia authorization: https://sepolia.etherscan.io/tx/0xb128ed2d774c524d563d43df63349fd8ea6c39742a36a7f9a24d1d8309dab6aa
- Creditcoin ingest: https://creditcoin-testnet.blockscout.com/tx/0x220f64a587451af1c425be74e644366b7784b9c26a7589cbfa412e4e69528062
- Sepolia execution: https://sepolia.etherscan.io/tx/0x16096b8bd03603994630c04afe09c1c25d2382e30338058c35d2f1333eb3feb7
- Creditcoin registry: https://creditcoin-testnet.blockscout.com/address/0x73fC164a9e7e7e3860E509e80B6A6ba838001275

The dashboard treats stored evidence as reference data and reports local artifact consistency separately from live Creditcoin registry verification.

## MCP integration

```bash
npm run mcp
```

The MCP v2 stdio surface exposes:

- `agentfirewall_check` — verifies `authorizationId`, `DeclaredIntent` and candidate transaction; never signs or broadcasts.
- `agentfirewall_execute` — optional Sepolia-only guarded execution, enabled with `AGENTFIREWALL_MCP_ENABLE_SEND=true`.

Signer material and controller approval remain process-local. No MCP tool accepts or returns a raw signer or private key.

A separate testnet MCP roundtrip produced:

| Stage | Transaction |
|---|---|
| Sepolia authorization | `0xb9c5730fbe8ea8ac78f32df3313998f5c81936263120a6d7a2ff98725959a183` |
| Creditcoin semantic ingest | `0x73f80ac837634e724c17f4f1df9c6faeb82996ce6588a2f665f4ad4340765be5` |
| Guarded Sepolia execution | `0xead4f51d00e69bfb5e63a9313333d100bb0edb50c68bf9ab8e27e6a48c9153cf` |

```text
mutated candidate    BLOCK    signerCallCount=0
canonical candidate  ALLOW    signerCallCount=1    mined
```

## Core files

- `src/guarded-signer.ts` — signing enforcement
- `src/verified-preflight.ts` — verified preflight
- `src/verified-authorization.ts` — authorization/commitment checks
- `src/authorization-registry.ts` — Creditcoin registry reader
- `src/controller-approval.ts` — EIP-712 controller verification
- `src/mcp-server.ts` — MCP integration
- `src/live-e2e.ts` — fresh testnet E2E
- `scripts/judge-verify.mjs` — deterministic runtime assertion
- `contracts/AuthorizationSource.sol` — source authorization
- `contracts/VerifiedAuthorizationRegistry.sol` — Creditcoin semantic registry

## Build provenance

AgentFirewall development started on September 7, 2026. `PROJECT_BASELINE.txt` records the initial project snapshot and separates it from the Attestcoin/Creditcoin, controller, live-E2E, MCP and hardened-signer work added for this build. No production adoption, revenue or audit claim is made.

## Known gaps

- one configured RPC is trusted per verified read path;
- authorization revocation/epochs are not implemented;
- proxy detection covers common layouts, not every custom proxy;
- testnet/reference implementation; not audited production custody software.

Technical detail: [`ARCHITECTURE.md`](ARCHITECTURE.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), [`VALIDATION.md`](VALIDATION.md), [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md).
