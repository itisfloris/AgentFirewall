import {
  analyzeTransaction,
  type SecurityPolicy,
  type TransactionInput
} from "./analyzer.js";

import {
  inspectOnchain
} from "./chain.js";

export type ChainInspector =
  typeof inspectOnchain;

export async function runPreflight(
  transaction: TransactionInput,
  policy: SecurityPolicy = {},
  inspector: ChainInspector = inspectOnchain
) {
  const local =
    analyzeTransaction(
      transaction,
      policy
    );

  const onchain =
    await inspector(
      transaction
    );

  let score =
    local.score;

  const findings = [
    ...local.findings
  ];

  if (
    onchain.destination.kind !== "contract" &&
    onchain.transaction.calldataBytes > 0
  ) {
    score += 45;

    findings.push({
      severity: "high" as const,
      code: "CALLDATA_TO_NON_CONTRACT",
      message:
        "Transaction contains calldata, but the destination currently has no contract bytecode."
    });
  }

  if (!onchain.simulation.ok) {
    score += 45;

    findings.push({
      severity: "high" as const,
      code: "SIMULATION_FAILED",
      message:
        "The transaction failed during eth_call simulation."
    });
  }

  if (!onchain.gasEstimate.ok) {
    score += 20;

    findings.push({
      severity: "medium" as const,
      code: "GAS_ESTIMATION_FAILED",
      message:
        "Gas estimation failed. The transaction may revert or depend on missing execution context."
    });
  }

  score =
    Math.min(
      score,
      100
    );

  const risk =
    score >= 70
      ? "critical"
      : score >= 40
        ? "high"
        : score >= 20
          ? "medium"
          : "low";

  const decision =
    score >= 70
      ? "BLOCK"
      : score >= 40
        ? "REVIEW"
        : "ALLOW";

  return {
    decision,
    risk,
    score,

    transactionSummary:
      local.transactionSummary,

    intent:
      local.intent,

    decoded:
      local.decoded,

    findings,

    onchain: {
      network:
        onchain.network,

      destination:
        onchain.destination,

      simulation:
        onchain.simulation,

      gasEstimate:
        onchain.gasEstimate,

      rpcSource:
        onchain.rpcSource
    }
  };
}
