import {
  mkdirSync,
  writeFileSync
} from "node:fs";

import {
  dirname
} from "node:path";

import type {
  LiveAuthorizationArtifact
} from "./live-demo.js";

export const LIVE_EVIDENCE_VERSION =
  "AgentFirewall.LiveEvidence.v1";

export const DEFAULT_LIVE_EVIDENCE_FILE =
  "build/live-evidence.json";

const SEPOLIA_EXPLORER =
  "https://sepolia.etherscan.io";

const CREDITCOIN_TESTNET_EXPLORER =
  "https://creditcoin-testnet.blockscout.com";

export type LiveJudgeEvidence = {
  version: typeof LIVE_EVIDENCE_VERSION;
  generatedAt: string;
  claim: string;
  build?: {
    sourceId?: string;
    sourceKind?: "git" | "standalone-sha256";
    sourceCommit?: string;
    sourceTreeClean?: boolean;
  };
  transactions?: {
    sourceAuthorization: string;
    creditcoinIngest: string;
    execution?: string;
  };
  controllerApproval?: {
    controller: string;
    executor: string;
    authoritySeparated: true;
  };
  guardedSigner?: {
    mutated: {
      simulation: "SUCCESS";
      decision: "BLOCK";
      signerCalled: false;
      signerCallCount: 0;
    };
    canonical: {
      simulation: "SUCCESS";
      decision: "ALLOW";
      signerCalled: true;
      signerCallCount: 1;
      transactionHash: string;
      blockNumber: string;
    };
  };
  authorization: {
    authorizationId: string;
    commitment: string;
  };
  source: {
    network: "sepolia";
    chainId: string;
    authorizationSource: string;
    transactionHash: string;
    blockNumber: string;
    transactionIndex: string | null;
    explorerTransaction: string;
    explorerContract: string;
  };
  creditcoin: {
    network: "creditcoin-testnet";
    registryAddress: string;
    transactionHash: string;
    blockNumber: string;
    sourceChainKey: string;
    sourceBlockNumber: string;
    transactionIndex: string;
    transactionKey: string;
    provenTransactionHash: string;
    proofPreflightVerified: boolean;
    explorerTransaction: string;
    explorerContract: string;
  };
  firewall: {
    mutatedExecutablePayload: {
      simulation: "SUCCESS";
      decision: "BLOCK";
      criticalFindingCodes: string[];
    };
    exactProofBackedPayload: {
      simulation: "SUCCESS";
      decision: "ALLOW";
      criticalFindingCodes: string[];
    };
  };
  execution?: {
    transactionHash: string;
    blockNumber: string;
    explorerTransaction: string;
  };
};

export function buildLiveJudgeEvidence(
  artifact: LiveAuthorizationArtifact
): LiveJudgeEvidence {
  if (!artifact.creditcoin) {
    throw new Error(
      "Cannot build live evidence before Creditcoin semantic ingest"
    );
  }

  if (!artifact.verification) {
    throw new Error(
      "Cannot build live evidence before the mutated/exact firewall verification pair"
    );
  }

  if (artifact.creditcoin.proofPreflightVerified !== true) {
    throw new Error(
      "Live evidence requires a successful Creditcoin native proof preflight"
    );
  }

  if (
    !artifact.verification.mutated.simulationOk ||
    artifact.verification.mutated.decision !== "BLOCK"
  ) {
    throw new Error(
      "Live evidence requires mutated payload simulation SUCCESS and firewall BLOCK"
    );
  }

  if (artifact.verification.mutated.criticalFindingCodes.length === 0) {
    throw new Error(
      "Live evidence requires at least one critical finding explaining the mutated payload BLOCK"
    );
  }

  if (
    !artifact.verification.exact.simulationOk ||
    artifact.verification.exact.decision !== "ALLOW"
  ) {
    throw new Error(
      "recorded ALLOW path is inconsistent"
    );
  }

  if (
    artifact.creditcoin.sourceBlockNumber !==
    artifact.source.blockNumber
  ) {
    throw new Error(
      `proof source block does not match the Sepolia publish block`
    );
  }

  if (
    artifact.source.transactionIndex !== undefined &&
    artifact.creditcoin.transactionIndex !==
      artifact.source.transactionIndex
  ) {
    throw new Error(
      `transaction index ${artifact.creditcoin.transactionIndex} != receipt index ${artifact.source.transactionIndex}`
    );
  }

  const evidence: LiveJudgeEvidence = {
    version: LIVE_EVIDENCE_VERSION,
    generatedAt: new Date().toISOString(),
    claim:
      "A successful Sepolia authorization receipt was proven through Creditcoin and semantically ingested; an executable mutation was BLOCKED while the authorized canonical execution commitment was ALLOWED.",
    ...(artifact.build
      ? {
          build: {
            ...artifact.build
          }
        }
      : {}),
    transactions: {
      sourceAuthorization:
        artifact.source.transactionHash,
      creditcoinIngest:
        artifact.creditcoin.transactionHash,
      ...(artifact.executionResult
        ? {
            execution:
              artifact.executionResult.transactionHash
          }
        : {})
    },
    ...(artifact.controllerApproval
      ? {
          controllerApproval: {
            controller:
              artifact.controllerApproval.controller,
            executor:
              artifact.controllerApproval.executor,
            authoritySeparated: true as const
          }
        }
      : {}),
    authorization: {
      authorizationId:
        artifact.source.authorizationId,
      commitment:
        artifact.source.commitment
    },
    source: {
      network: "sepolia",
      chainId:
        artifact.source.chainId,
      authorizationSource:
        artifact.source.authorizationSource,
      transactionHash:
        artifact.source.transactionHash,
      blockNumber:
        artifact.source.blockNumber,
      transactionIndex:
        artifact.source.transactionIndex ?? null,
      explorerTransaction:
        `${SEPOLIA_EXPLORER}/tx/${artifact.source.transactionHash}`,
      explorerContract:
        `${SEPOLIA_EXPLORER}/address/${artifact.source.authorizationSource}`
    },
    creditcoin: {
      network: "creditcoin-testnet",
      registryAddress:
        artifact.creditcoin.registryAddress,
      transactionHash:
        artifact.creditcoin.transactionHash,
      blockNumber:
        artifact.creditcoin.blockNumber,
      sourceChainKey:
        artifact.creditcoin.sourceChainKey,
      sourceBlockNumber:
        artifact.creditcoin.sourceBlockNumber,
      transactionIndex:
        artifact.creditcoin.transactionIndex,
      transactionKey:
        artifact.creditcoin.transactionKey,
      provenTransactionHash:
        artifact.creditcoin.provenTransactionHash,
      proofPreflightVerified:
        artifact.creditcoin.proofPreflightVerified === true,
      explorerTransaction:
        `${CREDITCOIN_TESTNET_EXPLORER}/tx/${artifact.creditcoin.transactionHash}`,
      explorerContract:
        `${CREDITCOIN_TESTNET_EXPLORER}/address/${artifact.creditcoin.registryAddress}`
    },
    firewall: {
      mutatedExecutablePayload: {
        simulation: "SUCCESS",
        decision: "BLOCK",
        criticalFindingCodes:
          artifact.verification.mutated.criticalFindingCodes
      },
      exactProofBackedPayload: {
        simulation: "SUCCESS",
        decision: "ALLOW",
        criticalFindingCodes:
          artifact.verification.exact.criticalFindingCodes
      }
    }
  };

  if (
    artifact.executionResult &&
    artifact.verification.mutated.signerCallCount === 0 &&
    artifact.verification.exact.signerCallCount === 1
  ) {
    evidence.guardedSigner = {
      mutated: {
        simulation: "SUCCESS",
        decision: "BLOCK",
        signerCalled: false,
        signerCallCount: 0
      },
      canonical: {
        simulation: "SUCCESS",
        decision: "ALLOW",
        signerCalled: true,
        signerCallCount: 1,
        transactionHash:
          artifact.executionResult.transactionHash,
        blockNumber:
          artifact.executionResult.blockNumber
      }
    };
  }

  if (artifact.executionResult) {
    evidence.execution = {
      transactionHash:
        artifact.executionResult.transactionHash,
      blockNumber:
        artifact.executionResult.blockNumber,
      explorerTransaction:
        `${SEPOLIA_EXPLORER}/tx/${artifact.executionResult.transactionHash}`
    };
  }

  return evidence;
}



export function historicalEvidenceMatchesArtifacts(
  input: {
    deployment: {
      source?: {
        chainId: string;
        address: string;
      };
      semanticRegistry?: {
        sourceChainKey: string;
        sourceChainId: string;
        trustedAuthorizationSource: string;
        address: string;
      };
    } | null;
    artifact: LiveAuthorizationArtifact;
    evidence: LiveJudgeEvidence;
    registryRecord: {
      commitment: string;
      sourceChainKey: string;
      sourceBlockNumber: string;
      transactionIndex: string;
      validUntil: string;
      verified?: boolean;
    };
    requireVerifiedRecord?: boolean;
  }
): boolean {
  try {
    const canonical =
      buildLiveJudgeEvidence(input.artifact);

    const source =
      input.deployment?.source;
    const registry =
      input.deployment?.semanticRegistry;
    const record =
      input.registryRecord;

    if (
      !source ||
      !registry ||
      (input.requireVerifiedRecord !== false && record.verified !== true)
    ) {
      return false;
    }

    const nonZeroBytes32 =
      (value: string) =>
        /^0x[0-9a-fA-F]{64}$/.test(value) &&
        !/^0x0{64}$/i.test(value);

    if (
      !nonZeroBytes32(input.evidence.authorization.authorizationId) ||
      !nonZeroBytes32(input.evidence.authorization.commitment) ||
      !nonZeroBytes32(input.evidence.source.transactionHash) ||
      !nonZeroBytes32(input.evidence.creditcoin.transactionHash) ||
      !nonZeroBytes32(input.evidence.creditcoin.transactionKey) ||
      !nonZeroBytes32(input.evidence.creditcoin.provenTransactionHash)
    ) {
      return false;
    }

    const lower =
      (value: string) => value.toLowerCase();

    const sameStringArray = (
      left: readonly string[],
      right: readonly string[]
    ) =>
      left.length === right.length &&
      left.every((value, index) => value === right[index]);

    const canonicalExecution = canonical.execution;
    const evidenceExecution = input.evidence.execution;
    const executionMatches = canonicalExecution
      ? Boolean(
          evidenceExecution &&
          lower(evidenceExecution.transactionHash) ===
            lower(canonicalExecution.transactionHash) &&
          evidenceExecution.blockNumber ===
            canonicalExecution.blockNumber
        )
      : evidenceExecution === undefined;

    const canonicalTransactions = canonical.transactions;
    const evidenceTransactions = input.evidence.transactions;
    const transactionsMatch = Boolean(
      canonicalTransactions &&
      evidenceTransactions &&
      lower(evidenceTransactions.sourceAuthorization) ===
        lower(canonicalTransactions.sourceAuthorization) &&
      lower(evidenceTransactions.creditcoinIngest) ===
        lower(canonicalTransactions.creditcoinIngest) &&
      (canonicalTransactions.execution
        ? Boolean(
            evidenceTransactions.execution &&
            lower(evidenceTransactions.execution) ===
              lower(canonicalTransactions.execution)
          )
        : evidenceTransactions.execution === undefined)
    );

    const buildMatches = canonical.build
      ? Boolean(
          input.evidence.build &&
          input.evidence.build.sourceId ===
            canonical.build.sourceId &&
          input.evidence.build.sourceKind ===
            canonical.build.sourceKind &&
          input.evidence.build.sourceCommit ===
            canonical.build.sourceCommit &&
          input.evidence.build.sourceTreeClean ===
            canonical.build.sourceTreeClean
        )
      : input.evidence.build === undefined;

    const controllerMatches = canonical.controllerApproval
      ? Boolean(
          input.evidence.controllerApproval &&
          lower(input.evidence.controllerApproval.controller) ===
            lower(canonical.controllerApproval.controller) &&
          lower(input.evidence.controllerApproval.executor) ===
            lower(canonical.controllerApproval.executor) &&
          input.evidence.controllerApproval.authoritySeparated === true
        )
      : input.evidence.controllerApproval === undefined;

    const guardedSignerMatches = canonical.guardedSigner
      ? Boolean(
          input.evidence.guardedSigner &&
          input.evidence.guardedSigner.mutated.simulation ===
            canonical.guardedSigner.mutated.simulation &&
          input.evidence.guardedSigner.mutated.decision ===
            canonical.guardedSigner.mutated.decision &&
          input.evidence.guardedSigner.mutated.signerCalled === false &&
          input.evidence.guardedSigner.mutated.signerCallCount === 0 &&
          input.evidence.guardedSigner.canonical.simulation ===
            canonical.guardedSigner.canonical.simulation &&
          input.evidence.guardedSigner.canonical.decision ===
            canonical.guardedSigner.canonical.decision &&
          input.evidence.guardedSigner.canonical.signerCalled === true &&
          input.evidence.guardedSigner.canonical.signerCallCount === 1 &&
          lower(input.evidence.guardedSigner.canonical.transactionHash) ===
            lower(canonical.guardedSigner.canonical.transactionHash) &&
          input.evidence.guardedSigner.canonical.blockNumber ===
            canonical.guardedSigner.canonical.blockNumber
        )
      : input.evidence.guardedSigner === undefined;

    return (
      input.evidence.version === LIVE_EVIDENCE_VERSION &&
      transactionsMatch &&
      buildMatches &&
      controllerMatches &&
      guardedSignerMatches &&
      lower(source.address) ===
        lower(registry.trustedAuthorizationSource) &&
      lower(source.address) ===
        lower(canonical.source.authorizationSource) &&
      source.chainId === canonical.source.chainId &&
      lower(registry.address) ===
        lower(canonical.creditcoin.registryAddress) &&
      registry.sourceChainKey ===
        canonical.creditcoin.sourceChainKey &&
      registry.sourceChainId === canonical.source.chainId &&
      lower(input.evidence.authorization.authorizationId) ===
        lower(canonical.authorization.authorizationId) &&
      lower(input.evidence.authorization.commitment) ===
        lower(canonical.authorization.commitment) &&
      lower(input.evidence.source.authorizationSource) ===
        lower(canonical.source.authorizationSource) &&
      input.evidence.source.chainId ===
        canonical.source.chainId &&
      lower(input.evidence.source.transactionHash) ===
        lower(canonical.source.transactionHash) &&
      input.evidence.source.blockNumber ===
        canonical.source.blockNumber &&
      input.evidence.source.transactionIndex ===
        canonical.source.transactionIndex &&
      lower(input.evidence.creditcoin.registryAddress) ===
        lower(canonical.creditcoin.registryAddress) &&
      lower(input.evidence.creditcoin.transactionHash) ===
        lower(canonical.creditcoin.transactionHash) &&
      input.evidence.creditcoin.blockNumber ===
        canonical.creditcoin.blockNumber &&
      input.evidence.creditcoin.sourceChainKey ===
        canonical.creditcoin.sourceChainKey &&
      input.evidence.creditcoin.sourceBlockNumber ===
        canonical.creditcoin.sourceBlockNumber &&
      input.evidence.creditcoin.transactionIndex ===
        canonical.creditcoin.transactionIndex &&
      lower(input.evidence.creditcoin.transactionKey) ===
        lower(canonical.creditcoin.transactionKey) &&
      lower(input.evidence.creditcoin.provenTransactionHash) ===
        lower(canonical.creditcoin.provenTransactionHash) &&
      input.evidence.creditcoin.proofPreflightVerified === true &&
      input.evidence.firewall.mutatedExecutablePayload.simulation ===
        canonical.firewall.mutatedExecutablePayload.simulation &&
      input.evidence.firewall.mutatedExecutablePayload.decision ===
        canonical.firewall.mutatedExecutablePayload.decision &&
      sameStringArray(
        input.evidence.firewall.mutatedExecutablePayload.criticalFindingCodes,
        canonical.firewall.mutatedExecutablePayload.criticalFindingCodes
      ) &&
      input.evidence.firewall.exactProofBackedPayload.simulation ===
        canonical.firewall.exactProofBackedPayload.simulation &&
      input.evidence.firewall.exactProofBackedPayload.decision ===
        canonical.firewall.exactProofBackedPayload.decision &&
      sameStringArray(
        input.evidence.firewall.exactProofBackedPayload.criticalFindingCodes,
        canonical.firewall.exactProofBackedPayload.criticalFindingCodes
      ) &&
      executionMatches &&
      lower(record.commitment) ===
        lower(canonical.authorization.commitment) &&
      record.sourceChainKey ===
        canonical.creditcoin.sourceChainKey &&
      record.sourceBlockNumber ===
        canonical.creditcoin.sourceBlockNumber &&
      record.transactionIndex ===
        canonical.creditcoin.transactionIndex &&
      record.validUntil ===
        input.artifact.execution.declaredIntent.validUntil
    );
  } catch {
    return false;
  }
}

export function writeLiveJudgeEvidence(
  artifact: LiveAuthorizationArtifact,
  path = process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
    DEFAULT_LIVE_EVIDENCE_FILE
): string {
  const evidence =
    buildLiveJudgeEvidence(artifact);

  mkdirSync(dirname(path), {
    recursive: true
  });

  writeFileSync(
    path,
    `${JSON.stringify(evidence, null, 2)}\n`,
    "utf8"
  );

  return path;
}
