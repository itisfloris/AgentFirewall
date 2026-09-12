# Implementation notes

Most security-critical code sits between `GuardedSigner.guardAndSendVerified()` and `runVerifiedPreflight()`. The HTTP API and dashboard are not involved in runtime signing.

## Signing flow

The caller supplies only the requested execution (`to`, `data`, `value`) plus authorization/controller material. Address, chain id and pending nonce come from the signer boundary and execution provider.

After reading the pending nonce, `GuardedSigner` reserves `(chainId, sender, nonce)` in a process-wide in-memory set before asynchronous preflight begins. A concurrent call for the same tuple fails before `signTransaction()`. The reservation is released in `finally` on success or failure.

`populateTransaction()` is called once. The result is copied into the supported immutable transaction envelope. Fee limits are checked before verified preflight.

Preflight loads the Creditcoin record, reconstructs the authorization commitment, decodes the actual call and reads target state from a pinned EVM block. A failing preflight returns before signing.

The controller approval uses EIP-712 domain version 2. It binds the authorization/execution tuple plus the four configured fee ceilings. A signature created for one fee policy cannot authorize a different fee policy.

Immediately before signing, the wrapper rechecks chain id, pending nonce, expiry and target bytecode. If a secondary execution provider is supplied, the same block hash, pending nonce and target code hash must agree across both providers or execution fails closed. The signed raw transaction is parsed and compared with the expected unsigned envelope before the exact raw bytes are broadcast.

## Signer trust boundary

`GuardedSigner` depends on the minimal `TransactionSignerBoundary` interface rather than a concrete wallet/private-key implementation. `ExternalTransactionSignerAdapter` allows the signing operation to be delegated to another process or custody system while the firewall remains independent of key ownership.

The repository does not implement or claim HSM/KMS isolation. The in-process wallet adapters used by live demo tooling are one deployment option, not a requirement of `GuardedSigner`.

## Authorization and policy semantics

`Authorization.v3` includes execution chain, executor, nonce, expiry, action, target, target code hash, asset/counterparty fields, amount or flag, calldata hash and native value.

Verified authorization is necessary but not sufficient. The local analyzer and hard policy remain an independent deny layer. A valid Creditcoin record and controller signature therefore do not guarantee execution. This is intentional for cases such as `setApprovalForAll(true)`, which can still be blocked by local risk policy.

Gas-market fields remain outside the deployed `Authorization.v3` commitment to preserve historical compatibility. Controller approval v2 binds `maxGasLimit`, `maxFeePerGasWei`, `maxPriorityFeePerGasWei` and `maxTotalFeeWei`. Exact network-selected fee fields are still constrained locally by `FeeSafetyPolicy`.
The bundled historical live evidence contains a v1 controller approval and is not rewritten or described as fee-bound v2 evidence. Fresh controller approvals created by the current tooling use v2.

## Source record

`AuthorizationSource` emits the source event on Sepolia. Attestcoin proves the source transaction. `VerifiedAuthorizationRegistry` on Creditcoin CC3 reconstructs the record from the proven receipt/log bytes.

The verified reader checks configured registry/source trust anchors and registry runtime code. A local bundled artifact consistency check is not treated as an independently verified registry record.

## RPC model

The normal verified read path trusts its configured RPC source. `GuardedSigner` supports an optional second execution provider for the final chain/nonce/block/code recheck. When configured, disagreement fails closed. This is not a general RPC quorum and does not independently replicate Creditcoin proof verification unless the deployment configures a separate verified reader.

RPC error sanitization must not emit credentials embedded in endpoint URLs.

## Chain snapshot, token semantics and proxies

`src/chain.ts` pins preflight reads to one block and checks block identity after the reads. Gas estimation is advisory and is not part of that snapshot guarantee.

Known EIP-1967/beacon and EIP-1167 proxy shapes fail closed in verified mode because mutable implementation state is not represented in `Authorization.v3`. The detector is intentionally limited and is not a general proxy/delegatecall classifier.

ERC-20 actions are bound to exact calldata derived from the declared supported action. This prevents calldata mutation for the supported shapes but does not prove arbitrary target contracts implement standard ERC-20 semantics.

## Solidity validation

The mandatory npm judge path runs `contracts:security`. It validates shipped contract source/artifact invariants, replay/expiry/sender checks, critical ABI surface and forbidden primitives without downloading tools at runtime.

`contracts:compile` is an optional developer rebuild path. It never runs `npm exec`, `npm install` or another package acquisition command. It requires exact local `solc@0.8.28` and `@gluwa/asc-contracts@0.2.1`. Those optional compiler packages are outside the application lockfile, so full Solidity rebuild hermeticity is not claimed.
