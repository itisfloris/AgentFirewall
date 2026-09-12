# Judge demo — 90 to 150 seconds

## 0. Start on the dashboard

Run `npm run dev` and open `http://127.0.0.1:8787`.

The screen is deliberately the five-part security boundary:

```text
Authorization -> Attestation -> Controller -> Agent -> Signer
```

Do not start in the terminal or generic transaction analyzer.

## 1. State the problem

Use one sentence:

> A transaction can execute successfully and still be unauthorized. AgentFirewall lets an AI agent propose transactions without giving compromised agent logic unconditional wallet authority.

## 2. Show the compromised proposal

Select **Compromised candidate**.

Point at:

```text
EVM simulation       SUCCESS
AgentFirewall        BLOCK
signTransaction()    NOT CALLED · 0 calls
```

The important contrast is executability versus authorization. Do not claim that the mutated transaction could never have been authorized by anybody; the evidence shows that it does not match the proof-backed authorization referenced by this run.

## 3. Show where authorization came from

Use the evidence panel to open:

1. the fresh Sepolia `AuthorizationSource` publish transaction;
2. the Creditcoin semantic ingest transaction.

Explain that Creditcoin is not trusting JSON supplied by the app; the registry record is derived from the proven Sepolia transaction.

## 4. Show controller separation

Point at **Controller ≠ Executor**.

The controller approval is EIP-712 and binds the authorization id, commitment, executor, execution chain, nonce, expiry, registry and source chain key.

## 5. Show the canonical proposal

Select **Authorized candidate**.

Point at:

```text
EVM simulation       SUCCESS
AgentFirewall        ALLOW
signTransaction()    CALLED ONCE · 1 call
```

Open the mined Sepolia execution transaction from the evidence panel.

## 6. Show the real agent integration

Briefly show `src/mcp-server.ts` or an MCP host connected with:

```text
agentfirewall_check
agentfirewall_execute
```

The model supplies only `authorizationId + DeclaredIntent + candidateTransaction`. The executor key and controller approval stay inside the AgentFirewall process. There is no raw-signer tool.

## 7. Finish on the evidence artifact

Open `build/live-evidence.json` and point at:

```text
transactions.sourceAuthorization
transactions.creditcoinIngest
transactions.execution
controllerApproval.authoritySeparated = true
guardedSigner.mutated.signerCallCount = 0
guardedSigner.canonical.signerCallCount = 1
```

That file records the on-chain authorization, Creditcoin ingest, execution result, controller separation and signer-call evidence for the live run.

## Fresh run command

After setting the testnet environment variables:

```bash
npm run live:e2e
```

It creates a new one-shot authorization and cannot reuse an execution nonce that has already been spent.

## 8. Close with the product case

Use two short sentences:

> The target user is any wallet or agent-infrastructure team that wants autonomous software to prepare transactions without becoming the signing authority. Creditcoin is the verification plane: even when execution happens on another EVM chain, the agent's permission can be proven and enforced through Attestcoin before the signer is touched.

Do not claim production users, revenue, audits or custody-grade readiness unless those facts exist outside this repository and can be independently shown.
