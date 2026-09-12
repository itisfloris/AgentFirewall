import {
  readFileSync
} from "node:fs";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  DEFAULT_LIVE_EVIDENCE_FILE,
  historicalEvidenceMatchesArtifacts,
  type LiveJudgeEvidence
} from "./live-evidence.js";

import {
  loadLiveDeploymentArtifact
} from "./live-deployment.js";

function main(): void {
  const artifactPath =
    process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
    DEFAULT_LIVE_DEMO_FILE;
  const evidencePath =
    process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
    DEFAULT_LIVE_EVIDENCE_FILE;

  const artifact = JSON.parse(
    readFileSync(artifactPath, "utf8")
  ) as LiveAuthorizationArtifact;
  const evidence = JSON.parse(
    readFileSync(evidencePath, "utf8")
  ) as LiveJudgeEvidence;
  const deployment =
    loadLiveDeploymentArtifact();

  if (artifact.version !== LIVE_DEMO_ARTIFACT_VERSION) {
    throw new Error(
      `Unsupported live authorization artifact version: ${String(artifact.version)}`
    );
  }

  if (!artifact.creditcoin) {
    throw new Error(
      "Historical artifact does not contain Creditcoin semantic ingest coordinates"
    );
  }

  const valid =
    historicalEvidenceMatchesArtifacts({
      deployment,
      artifact,
      evidence,
      registryRecord: {
        commitment: artifact.source.commitment,
        sourceChainKey: artifact.creditcoin.sourceChainKey,
        sourceBlockNumber: artifact.creditcoin.sourceBlockNumber,
        transactionIndex: artifact.creditcoin.transactionIndex,
        validUntil: artifact.execution.declaredIntent.validUntil ?? "0"
      },
      requireVerifiedRecord: false
    });

  if (!valid) {
    throw new Error(
      "Local historical evidence consistency check failed"
    );
  }

  console.log(
    JSON.stringify(
      {
        localEvidenceConsistency: true,
        note:
          "This command validates consistency of bundled artifacts only. Use npm run live:evidence for network-backed verification.",
        authorizationId: artifact.source.authorizationId,
        sourceTransaction: evidence.source.explorerTransaction,
        creditcoinTransaction: evidence.creditcoin.explorerTransaction,
        execution: evidence.execution ?? null
      },
      null,
      2
    )
  );
}

try {
  main();
} catch (error) {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
}
