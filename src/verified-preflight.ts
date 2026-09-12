import type {
  SecurityPolicy,
  TransactionInput
} from "./analyzer.js";

import type {
  DeclaredIntent
} from "./intent.js";

import {
  runIntentPreflight
} from "./intent-preflight.js";

import type {
  ChainInspector
} from "./preflight.js";

import {
  inspectVerifiedOnchain
} from "./chain.js";

import {
  critical,
  evaluateVerifiedAuthorization,
  type AuthorizationFinding,
  type VerifiedAuthorizationReader
} from "./verified-authorization.js";

export {
  evaluateVerifiedAuthorization,
  normalizeAuthorizationId,
  type AuthorizationFinding,
  type AuthorizationIntegrity,
  type VerifiedAuthorizationReader,
  type VerifiedAuthorizationRecord
} from "./verified-authorization.js";

export {
  CreditcoinAuthorizationRegistryReader,
  createConfiguredAuthorizationReader,
  normalizeSemanticRegistryTrustConfig,
  type SemanticRegistryTrustConfig
} from "./authorization-registry.js";

export async function runVerifiedPreflight(
  authorizationId: string,
  declaredIntent: DeclaredIntent,
  transaction: TransactionInput,
  reader: VerifiedAuthorizationReader,
  policy: SecurityPolicy = {},
  inspector?: ChainInspector
) {
  const effectiveInspector =
    inspector ?? inspectVerifiedOnchain;

  const intentResult =
    await runIntentPreflight(
      declaredIntent,
      transaction,
      policy,
      effectiveInspector
    );

  const securityFindings: AuthorizationFinding[] = [];

  const chainTimestamp =
    intentResult.onchain.network.timestamp;

  if (
    !Number.isSafeInteger(chainTimestamp) ||
    chainTimestamp < 0
  ) {
    securityFindings.push(
      critical(
        "CHAIN_SNAPSHOT_TIMESTAMP_UNAVAILABLE",
        "Verified enforcement requires a timestamp from the pinned execution-chain block snapshot."
      )
    );
  }

  const proxy =
    intentResult.onchain.destination.proxy;

  if (proxy?.assessment === "detected") {
    securityFindings.push(
      critical(
        "UPGRADEABLE_PROXY_UNSUPPORTED",
        `Verified target ${intentResult.onchain.destination.address} is detected as ${proxy.kind}; Authorization.v3 binds proxy runtime code but not mutable implementation state, so enforcement fails closed.`
      )
    );
  } else if (
    intentResult.onchain.destination.kind === "contract" &&
    proxy?.assessment === "unknown"
  ) {
    securityFindings.push(
      critical(
        "TARGET_PROXY_IDENTITY_UNAVAILABLE",
        "AgentFirewall could not rule out a common upgradeable-proxy pattern at the pinned block snapshot."
      )
    );
  }

  const authorization =
    await evaluateVerifiedAuthorization(
      authorizationId,
      declaredIntent,
      intentResult.actualEffect,
      intentResult.onchain.destination.codeHash,
      reader,
      Number.isSafeInteger(chainTimestamp)
        ? chainTimestamp
        : 0
    );

  authorization.findings.push(...securityFindings);
  authorization.ok = authorization.findings.length === 0;
  authorization.decision = authorization.ok ? "ALLOW" : "BLOCK";

  const hardBlocked =
    !authorization.ok ||
    !intentResult.integrity.ok;

  return {
    ...intentResult,
    decision:
      hardBlocked
        ? "BLOCK" as const
        : intentResult.decision,
    risk:
      hardBlocked
        ? "critical" as const
        : intentResult.risk,
    score:
      hardBlocked
        ? 100
        : intentResult.score,
    authorization,
    findings: [
      ...authorization.findings,
      ...intentResult.findings
    ]
  };
}
