import type {
  SecurityPolicy,
  TransactionInput
} from "./analyzer.js";

import {
  decodeActualEffect,
  matchDeclaredIntent,
  type DeclaredIntent
} from "./intent.js";

import {
  runPreflight,
  type ChainInspector
} from "./preflight.js";

export async function runIntentPreflight(
  declaredIntent: DeclaredIntent,
  transaction: TransactionInput,
  policy: SecurityPolicy = {},
  inspector?: ChainInspector
) {
  const actualEffect =
    decodeActualEffect(transaction);

  const integrity =
    matchDeclaredIntent(
      declaredIntent,
      actualEffect
    );

  const baseline =
    await runPreflight(
      transaction,
      policy,
      inspector
    );

  const hardBlocked =
    !integrity.ok;

  const findings = [
    ...integrity.findings,
    ...baseline.findings
  ];

  return {
    decision:
      hardBlocked
        ? "BLOCK" as const
        : baseline.decision,

    risk:
      hardBlocked
        ? "critical" as const
        : baseline.risk,

    score:
      hardBlocked
        ? 100
        : baseline.score,

    transactionSummary:
      baseline.transactionSummary,

    intent:
      baseline.intent,

    decoded:
      baseline.decoded,

    declaredIntent,
    actualEffect,
    integrity,
    findings,
    onchain:
      baseline.onchain
  };
}
