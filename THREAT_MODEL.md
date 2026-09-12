# Threat model

This document states the security assumptions and remaining limitations of the guarded signer.

## Assumptions

- agent code cannot bypass `GuardedSigner` and call the executor signer directly
- controller authority is separate from executor authority
- configured RPC endpoints are trusted unless an independent secondary execution provider is configured
- registry/source addresses and runtime code hashes are configured correctly
- Ethereum/Creditcoin consensus, ethers cryptography, Attestcoin verification and the upstream decoder are trusted dependencies

## Enforced boundaries

- exact intent/call/value/recipient matching for supported actions
- source authorization nonce and expiry binding
- controller/executor separation
- EIP-712 controller approval v2 binding the fee ceilings
- in-process sender/chain/nonce reservation before asynchronous preflight
- pre-sign chain, nonce, expiry and target-code recheck
- optional secondary execution RPC agreement on chain, nonce, pinned block and target code
- immutable unsigned transaction comparison after signing
- common proxy forms fail closed in verified mode
- RPC error sanitization

Verified authorization is necessary but not sufficient. Local hard policy and analyzer deny rules remain an independent deny layer. A valid proof and controller approval can therefore still be blocked.

## Remaining limitations

- nonce reservation is in-process only; multiple OS processes or hosts need an external shared reservation/nonce service
- the repository defines an external signer boundary but does not provide or claim HSM/KMS isolation
- the default deployment can still trust one execution RPC and one Creditcoin RPC; the optional secondary execution provider is not a full quorum
- no independent multi-RPC quorum is implemented for Creditcoin registry/source verification
- exact network-selected gas fields are not inside deployed `Authorization.v3`; controller approval v2 binds fee ceilings instead
- existing historical `Authorization.v3` evidence has no explicit revocation epoch; nonce and expiry remain its lifetime controls
- ERC-20 handling binds supported calldata shapes but cannot prove arbitrary contracts implement standard token semantics
- proxy detection covers common EIP-1967/beacon and EIP-1167 layouts, not every delegatecall/custom proxy design
- state can change after signing and before inclusion
- host compromise can bypass process-level assumptions
- the mandatory Solidity security path performs reproducible source/artifact invariant checks, not formal verification, fuzzing or full static analysis
- optional Solidity recompilation requires exact external compiler/decoder packages and is not claimed fully hermetic

`provenTransactionHash` in the deployed registry is `keccak256(encodedTransaction)` from the Attestcoin proof payload, not the canonical Ethereum transaction hash.
