# BUIDL CTC submission copy

This file contains ready-to-paste product copy for the BUIDL CTC 2026 Fall submission.

## One-line pitch

AgentFirewall is a proof-backed execution firewall that lets AI agents propose EVM transactions without giving them unconditional wallet authority.

## Short description

AgentFirewall separates transaction proposal from transaction authority. A source-chain authorization is proven through Attestcoin and converted into a semantic authorization on Creditcoin. An AI/MCP agent may then propose a candidate transaction, but `GuardedSigner` refuses to call the signer unless the candidate exactly matches the verified authorization, an independent EIP-712 controller approval and local hard policy. In the bundled judge path, a maliciously mutated transaction simulates successfully but is blocked with zero signer calls; the canonical transaction is allowed and reaches the signer exactly once.

## Problem

Simulation tells an autonomous agent whether a transaction can execute. It does not prove that the exact recipient, target, calldata, value, nonce, runtime code and fee envelope were authorized. If a compromised planner or tool can mutate those fields before a raw signer is called, “the transaction simulated successfully” is not a security boundary.

## Solution

AgentFirewall turns verified cross-chain authorization into a capability enforced immediately before signing:

```text
Sepolia authorization
-> Attestcoin proof
-> Creditcoin VerifiedAuthorizationRegistry
-> independent controller approval
-> AI/MCP proposal
-> GuardedSigner
-> BLOCK before signer, or ALLOW and sign exactly once
```

## Attestcoin integration

Attestcoin is load-bearing. `VerifiedAuthorizationRegistry` calls Creditcoin's native BlockProver at `0x0000000000000000000000000000000000000FD2`, then decodes the proven source transaction and records only the authorization semantics derived from that verified transaction. The live client obtains a proof from Creditcoin's Proof Builder endpoint and preflights it against the same native verification surface before registry submission.

Without Attestcoin/Creditcoin, the signer would have no cryptographic link between a foreign-chain authorization and its local execution decision.

## Why Creditcoin

Creditcoin acts as the verification/authorization plane for autonomous execution. The eventual business transaction can execute on another EVM chain while Creditcoin verifies the cross-chain authority that permits it. That makes Creditcoin useful to agent-wallet infrastructure even when final transaction volume lives elsewhere.

## AI-track fit

The agent is the untrusted transaction proposer. AgentFirewall is the cryptographic authorization boundary between the agent and the signer. The MCP adapter accepts `authorizationId + DeclaredIntent + candidateTransaction`; it never exposes or accepts the raw signer. Cryptographically verified cross-chain data determines whether an AI-proposed action is eligible to trigger an on-chain transaction.

## Product story

An autonomous agent prepares a valid-looking transfer. The transaction simulates successfully, but a compromised planner or tool has changed the recipient, calldata, value or another execution-critical field. AgentFirewall compares that concrete proposal with the proof-backed authorization at the final signing boundary. The mutated transaction is blocked before the private key is used; the canonical transaction is allowed and reaches the signer exactly once.

## Target users and ecosystem expansion

The initial users are agent-wallet infrastructure, MCP/agent-framework maintainers, automated treasuries, DeFi automation and applications that delegate transaction preparation to autonomous software while keeping signing authority outside the agent. The expansion thesis is concrete: Creditcoin can secure autonomous transaction volume whose final execution occurs on other EVM chains, because Creditcoin supplies the cross-chain verification and authorization plane rather than needing to be the destination chain.

## Evidence

Deterministic judge command: `npm run judge:verify`

Expected decisive result:

```text
COMPROMISED : SUCCESS -> BLOCK -> signTransaction calls 0
AUTHORIZED  : SUCCESS -> ALLOW -> signTransaction calls 1
```

Historical live testnet evidence:

- Sepolia authorization: `0xb128ed2d774c524d563d43df63349fd8ea6c39742a36a7f9a24d1d8309dab6aa`
- Creditcoin ingest: `0x220f64a587451af1c425be74e644366b7784b9c26a7589cbfa412e4e69528062`
- Sepolia execution: `0x16096b8bd03603994630c04afe09c1c25d2382e30338058c35d2f1333eb3feb7`

## Differentiator

The core difference is the location of enforcement: proof-backed authorization is checked at the signing boundary, after the agent has proposed a concrete transaction. A transaction that is executable but unauthorized does not reach `signTransaction()`.

## Honest scope

Testnet/reference implementation; not audited production custody software. No production-user or revenue claim is made in this submission.

## Originality / build provenance

AgentFirewall development started on September 7, 2026. The first project snapshot contained the transaction analyzer, policy checks, RPC inspection, dashboard, SDK guard and mock-wallet demo. The Attestcoin-backed cross-chain authorization flow, Creditcoin registry integration, controller approval, live E2E verification, MCP integration and hardened signer boundary were added during the current build. `PROJECT_BASELINE.txt` records this provenance.

## Submission assets

Public repository: https://github.com/itisfloris/AgentFirewall

The repository contains the complete source, deterministic judge path, technical documentation, dashboard and historical testnet evidence. No separate hosted web demo is required to reproduce the project: `npm run dev` serves the bundled visual demo locally.
