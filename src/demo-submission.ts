import {
  Interface,
  MaxUint256
} from "ethers";

import {
  commitmentFromDeclaredIntent
} from "./authorization.js";

import {
  inspectOnchain
} from "./chain.js";

import type {
  DeclaredIntent
} from "./intent.js";

import {
  runVerifiedPreflight,
  type VerifiedAuthorizationReader
} from "./verified-preflight.js";

import type {
  TransactionInput
} from "./analyzer.js";

const AUTHORIZATION_ID =
  `0x${"ab".repeat(32)}`;

const TOKEN =
  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const SENDER =
  "0x5555555555555555555555555555555555555555";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const ATTACKER =
  "0x9999999999999999999999999999999999999999";

const iface = new Interface([
  "function approve(address spender,uint256 amount)"
]);

function reader(
  intent: DeclaredIntent,
  options: {
    commitment?: string;
    verified?: boolean;
    validUntil?: string;
  } = {}
): VerifiedAuthorizationReader {
  return {
    async getAuthorization(authorizationId) {
      return {
        authorizationId,
        commitment:
          options.commitment ??
          commitmentFromDeclaredIntent(intent),
        verified: options.verified ?? true,
        sourceChainKey: "fixture-sepolia",
        sourceBlockNumber: "0",
        transactionIndex: "0",
        validUntil:
          options.validUntil ??
          intent.validUntil ??
          "0",
        registryAddress:
          "submission-demo-fixture",
        creditcoinChainId: "102031",
        rpcSource:
          "deterministic verified-record fixture"
      };
    }
  };
}

async function main() {
  console.log(
    "AGENTFIREWALL 1.0.0-rc.6 — DETERMINISTIC ATTACK MATRIX"
  );
  console.log(
    "Live Ethereum eth_call/estimateGas + deterministic verified-record fixture."
  );
  console.log(
    "Invariant: verified authorization = declared intent = canonical actual execution commitment."
  );

  const safeData =
    iface.encodeFunctionData(
      "approve",
      [SPENDER, 1n]
    );

  const probe = await inspectOnchain({
    chain: "ethereum",
    from: SENDER,
    to: TOKEN,
    nonce: "7",
    data: safeData,
    valueWei: "0"
  });

  if (!probe.simulation.ok) {
    throw new Error(
      "Live WETH approval probe did not simulate successfully; cannot run the submission demo."
    );
  }

  const liveCodeHash =
    probe.destination.codeHash;

  const chainTimestamp = BigInt(probe.network.timestamp);
  const validUntil =
    (chainTimestamp + 3600n).toString();

  const baseIntent: DeclaredIntent = {
    executionChainId: "1",
    sender: SENDER,
    executionNonce: "7",
    validUntil,
    targetCodeHash: liveCodeHash,
    action: "erc20_approve",
    target: TOKEN,
    asset: {
      kind: "erc20",
      address: TOKEN
    },
    spender: SPENDER,
    amountRaw: "1",
    method: "approve(address,uint256)"
  };

  const baseTransaction: TransactionInput = {
    chain: "ethereum",
    from: SENDER,
    to: TOKEN,
    nonce: "7",
    data: safeData,
    valueWei: "0"
  };

  type Scenario = {
    name: string;
    intent: DeclaredIntent;
    transaction: TransactionInput;
    authorizationReader: VerifiedAuthorizationReader;
    expect: "ALLOW" | "BLOCK";
  };

  const expiredIntent: DeclaredIntent = {
    ...baseIntent,
    validUntil:
      (chainTimestamp - 10n).toString()
  };

  const changedCodeIntent: DeclaredIntent = {
    ...baseIntent,
    targetCodeHash:
      `0x${"34".repeat(32)}`
  };

  const scenarios: Scenario[] = [
    {
      name: "SAFE — exact authorization / intent / payload",
      intent: baseIntent,
      transaction: baseTransaction,
      authorizationReader: reader(baseIntent),
      expect: "ALLOW"
    },
    {
      name: "ATTACK — amount mutated to MaxUint256",
      intent: baseIntent,
      transaction: {
        ...baseTransaction,
        data:
          iface.encodeFunctionData(
            "approve",
            [SPENDER, MaxUint256]
          )
      },
      authorizationReader: reader(baseIntent),
      expect: "BLOCK"
    },
    {
      name: "ATTACK — spender mutated",
      intent: baseIntent,
      transaction: {
        ...baseTransaction,
        data:
          iface.encodeFunctionData(
            "approve",
            [ATTACKER, 1n]
          )
      },
      authorizationReader: reader(baseIntent),
      expect: "BLOCK"
    },
    {
      name: "ATTACK — execution nonce replay/mutation",
      intent: baseIntent,
      transaction: {
        ...baseTransaction,
        nonce: "8"
      },
      authorizationReader: reader(baseIntent),
      expect: "BLOCK"
    },
    {
      name: "ATTACK — expired authorization",
      intent: expiredIntent,
      transaction: baseTransaction,
      authorizationReader: reader(expiredIntent),
      expect: "BLOCK"
    },
    {
      name: "ATTACK — forged Creditcoin registry commitment",
      intent: baseIntent,
      transaction: baseTransaction,
      authorizationReader: reader(
        baseIntent,
        {
          commitment:
            `0x${"cd".repeat(32)}`
        }
      ),
      expect: "BLOCK"
    },
    {
      name: "ATTACK — target runtime code changed",
      intent: changedCodeIntent,
      transaction: baseTransaction,
      authorizationReader: reader(changedCodeIntent),
      expect: "BLOCK"
    }
  ];

  let successfulSimulations = 0;
  let blockedAttacks = 0;
  let allowedCases = 0;

  for (const scenario of scenarios) {
    console.log("\n========================================");
    console.log(scenario.name);

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      scenario.intent,
      scenario.transaction,
      scenario.authorizationReader,
      { requireKnownCalldata: true }
    );

    if (result.onchain.simulation.ok) {
      successfulSimulations += 1;
    }

    console.log(
      `[SIMULATION] ${result.onchain.simulation.ok ? "SUCCESS" : "FAILED"}`
    );
    console.log(
      `[INTEGRITY] ${result.integrity.decision}`
    );
    console.log(
      `[AUTHORIZATION] ${result.authorization.decision}`
    );
    console.log(
      `[FIREWALL] ${result.decision} ${result.score}/100`
    );

    for (const finding of result.findings) {
      if (finding.severity === "critical") {
        console.log(
          `[${finding.code}] ${finding.message}`
        );
      }
    }

    if (result.decision === "ALLOW") {
      allowedCases += 1;
      console.log(
        "[INSPECTION ONLY] ALLOW recorded; this deterministic matrix does not invoke a signer."
      );
    } else if (scenario.expect === "BLOCK") {
      blockedAttacks += 1;
      console.log(
        "[INSPECTION ONLY] BLOCK recorded; no signing path exists in this fixture demo."
      );
    }

    if (result.decision !== scenario.expect) {
      throw new Error(
        `${scenario.name}: expected ${scenario.expect}, got ${result.decision}`
      );
    }

    if (
      scenario.expect === "BLOCK" &&
      !result.onchain.simulation.ok
    ) {
      throw new Error(
        `${scenario.name}: demo mutation did not simulate successfully`
      );
    }
  }

  if (allowedCases !== 1) {
    throw new Error(
      `Expected exactly one ALLOW inspection result; got ${allowedCases}`
    );
  }

  if (blockedAttacks !== 6) {
    throw new Error(
      `Expected 6 blocked attacks; got ${blockedAttacks}`
    );
  }

  if (successfulSimulations !== scenarios.length) {
    throw new Error(
      `expected ${scenarios.length} successful simulations, got ${successfulSimulations}`
    );
  }

  console.log("\n========================================");
  console.log(
    "DEMO ASSERTION PASSED: 7/7 EVM simulations succeeded; only the case matching the authorized canonical execution commitment received ALLOW; 6/6 simulated-success attacks received BLOCK. This command is inspection-only and does not sign."
  );
  console.log(
    "NOTE: the verified authorization record in this attack-matrix demo is a deterministic fixture. The separate Attestcoin proof path is tested/deployed independently; do not present this fixture as a live CC3 semantic registry."
  );
}

main().catch(error => {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
});
