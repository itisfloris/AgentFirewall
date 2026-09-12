import {
  JsonRpcProvider,
  Wallet,
  getAddress
} from "ethers";

import {
  readFileSync,
  writeFileSync
} from "node:fs";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  writeLiveJudgeEvidence
} from "./live-evidence.js";

import {
  createConfiguredAuthorizationReader,
  runVerifiedPreflight
} from "./verified-preflight.js";

import {
  GuardedSigner,
  GuardedSignerRejectedError,
  type FeeSafetyPolicy
} from "./guarded-signer.js";

import {
  observeSigner
} from "./signer-observer.js";

function loadArtifact(): {
  path: string;
  artifact: LiveAuthorizationArtifact;
} {
  const path =
    process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
    DEFAULT_LIVE_DEMO_FILE;

  const parsed =
    JSON.parse(
      readFileSync(path, "utf8")
    ) as LiveAuthorizationArtifact;

  if (
    parsed.version !==
    LIVE_DEMO_ARTIFACT_VERSION
  ) {
    throw new Error(
      `Unsupported live authorization artifact version: ${String(parsed.version)}`
    );
  }

  return {
    path,
    artifact: parsed
  };
}


function persistLiveEvidence(
  artifactPath: string,
  artifact: LiveAuthorizationArtifact
): string {
  writeFileSync(
    artifactPath,
    `${JSON.stringify(artifact, null, 2)}\n`,
    "utf8"
  );

  return writeLiveJudgeEvidence(
    artifact
  );
}

function requiredLiveSendEnv(
  name: string
): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `${name} is required for the GuardedSigner live-send path`
    );
  }

  return value;
}

function controllerForArtifact(
  artifact: LiveAuthorizationArtifact
): {
  controller: string;
  signature: string;
} {
  const controller =
    process.env.AGENTFIREWALL_TRUSTED_CONTROLLER?.trim() ||
    artifact.controllerApproval?.controller;
  const signature =
    process.env.AGENTFIREWALL_CONTROLLER_SIGNATURE?.trim() ||
    artifact.controllerApproval?.signature;

  if (!controller || !signature) {
    throw new Error(
      "Fresh GuardedSigner live send requires a controller approval. Run npm run controller:approve-live or provide AGENTFIREWALL_TRUSTED_CONTROLLER and AGENTFIREWALL_CONTROLLER_SIGNATURE."
    );
  }

  return { controller, signature };
}

function liveSendFeePolicy(): FeeSafetyPolicy {
  return {
    maxGasLimit: requiredLiveSendEnv("AGENTFIREWALL_MAX_GAS_LIMIT"),
    maxFeePerGasWei: requiredLiveSendEnv("AGENTFIREWALL_MAX_FEE_PER_GAS_WEI"),
    maxPriorityFeePerGasWei: requiredLiveSendEnv("AGENTFIREWALL_MAX_PRIORITY_FEE_PER_GAS_WEI"),
    maxTotalFeeWei: requiredLiveSendEnv("AGENTFIREWALL_MAX_TOTAL_FEE_WEI")
  };
}

async function main(): Promise<void> {
  const loaded =
    loadArtifact();

  const artifact =
    loaded.artifact;

  if (!artifact.creditcoin) {
    throw new Error(
      "Creditcoin proof record missing; run npm run attestcoin:ingest-authorization"
    );
  }

  const reader =
    createConfiguredAuthorizationReader();

  console.log(
    "AGENTFIREWALL LIVE VERIFIED-AUTHORIZATION DEMO"
  );
  console.log(
    `authorizationId=${artifact.source.authorizationId}`
  );
  console.log(
    "Proof-backed CC3 authorization will be checked against declared intent and the canonical Sepolia execution-critical commitment."
  );

  const attack =
    await runVerifiedPreflight(
      artifact.source.authorizationId,
      artifact.execution.declaredIntent,
      artifact.execution.mutatedTransaction,
      reader,
      {
        maxNativeValueWei: "1"
      }
    );

  console.log(
    `ATTACK simulation=${attack.onchain.simulation.ok ? "SUCCESS" : "FAILED"} firewall=${attack.decision}`
  );

  if (!attack.onchain.simulation.ok) {
    throw new Error(
      "demo mutation no longer simulates; choose another EOA and republish"
    );
  }

  if (attack.decision !== "BLOCK") {
    throw new Error(
      `Mutated transaction was expected to BLOCK, got ${attack.decision}`
    );
  }

  const safe =
    await runVerifiedPreflight(
      artifact.source.authorizationId,
      artifact.execution.declaredIntent,
      artifact.execution.transaction,
      reader,
      {
        maxNativeValueWei: "1"
      }
    );

  console.log(
    `SAFE simulation=${safe.onchain.simulation.ok ? "SUCCESS" : "FAILED"} firewall=${safe.decision}`
  );

  if (!safe.onchain.simulation.ok) {
    throw new Error(
      "Authorized canonical execution no longer simulates successfully"
    );
  }

  if (safe.decision !== "ALLOW") {
    const critical =
      safe.findings
        .filter(finding =>
          finding.severity === "critical"
        )
        .map(finding =>
          `${finding.code}: ${finding.message}`
        )
        .join("\n");

    throw new Error(
      `authorized execution returned ${safe.decision}\n${critical}`
    );
  }

  artifact.verification = {
    generatedAt:
      new Date().toISOString(),
    mutated: {
      simulationOk:
        attack.onchain.simulation.ok,
      decision:
        attack.decision,
      criticalFindingCodes:
        attack.findings
          .filter(finding =>
            finding.severity === "critical"
          )
          .map(finding => finding.code)
    },
    exact: {
      simulationOk:
        safe.onchain.simulation.ok,
      decision:
        safe.decision,
      criticalFindingCodes:
        safe.findings
          .filter(finding =>
            finding.severity === "critical"
          )
          .map(finding => finding.code)
    }
  };

  const evidencePath =
    persistLiveEvidence(
      loaded.path,
      artifact
    );

  console.log(
    `Judge evidence written to ${evidencePath}`
  );

  const liveSend =
    process.env.AGENTFIREWALL_LIVE_SEND ===
    "true";

  if (!liveSend) {
    console.log(
      "LIVE VERIFIED DEMO PASSED (DRY RUN): mutated simulated-success payload BLOCKED; authorized canonical execution commitment ALLOWED."
    );
    console.log(
      "A fresh broadcast is permitted only through GuardedSigner and additionally requires an independent controller approval plus explicit fee ceilings. Historical execution evidence is bundled only for reproducibility; do not rebroadcast it."
    );
    return;
  }

  const privateKey =
    process.env.AGENTFIREWALL_TESTNET_PRIVATE_KEY?.trim();

  if (!privateKey) {
    throw new Error(
      "AGENTFIREWALL_TESTNET_PRIVATE_KEY is required only for AGENTFIREWALL_LIVE_SEND=true"
    );
  }

  const sepolia =
    resolveNetwork("sepolia");

  const executionEndpoint =
    trustedRpcForEnforcement(sepolia);

  const provider =
    new JsonRpcProvider(
      executionEndpoint.url,
      Number(sepolia.chainId),
      { staticNetwork: true }
    );

  try {
    const detected =
      await provider.getNetwork();

    if (detected.chainId !== sepolia.chainId) {
      throw new Error(
        `Refusing live send: expected Sepolia ${sepolia.chainId}, got ${detected.chainId}`
      );
    }

    const wallet =
      new Wallet(
        privateKey,
        provider
      );

    const expectedSender =
      getAddress(
        artifact.execution.declaredIntent.sender ?? ""
      );

    if (wallet.address !== expectedSender) {
      throw new Error(
        `Live-send wallet ${wallet.address} does not match authorized sender ${expectedSender}`
      );
    }

    const currentNonce =
      await provider.getTransactionCount(
        wallet.address,
        "pending"
      );

    const authorizedNonce =
      BigInt(
        artifact.execution.transaction.nonce ?? "-1"
      );

    if (
      BigInt(currentNonce) !==
      authorizedNonce
    ) {
      throw new Error(
        `execution nonce changed: authorized=${authorizedNonce}, pending=${currentNonce}`
      );
    }

    const controllerApproval =
      controllerForArtifact(artifact);
    const observed =
      observeSigner(wallet);
    const guardedSigner =
      new GuardedSigner(
        observed.signer,
        reader,
        {
          trustedController:
            controllerApproval.controller,
          feePolicy:
            liveSendFeePolicy(),
          rpcSourceLabel:
            executionEndpoint.source
        }
      );

    let mutationBlockedByGuardedSigner = false;

    try {
      await guardedSigner.guardAndSendVerified(
        artifact.source.authorizationId,
        artifact.execution.declaredIntent,
        {
          to:
            artifact.execution.mutatedTransaction.to,
          data:
            artifact.execution.mutatedTransaction.data ?? "0x",
          valueWei:
            artifact.execution.mutatedTransaction.valueWei ?? "0"
        },
        controllerApproval.signature,
        {
          maxNativeValueWei: "1"
        }
      );
    } catch (error) {
      if (
        error instanceof GuardedSignerRejectedError &&
        error.code === "VERIFIED_PREFLIGHT_BLOCKED"
      ) {
        mutationBlockedByGuardedSigner = true;
      } else {
        throw error;
      }
    }

    if (!mutationBlockedByGuardedSigner) {
      throw new Error(
        "Mutated execution unexpectedly escaped the GuardedSigner block"
      );
    }

    if (observed.signTransactionCalls() !== 0) {
      throw new Error(
        `Mutated execution reached signTransaction ${observed.signTransactionCalls()} time(s)`
      );
    }

    artifact.verification.mutated.signerCallCount = 0;

    const guardedResult =
      await guardedSigner.guardAndSendVerified(
        artifact.source.authorizationId,
        artifact.execution.declaredIntent,
        {
          to:
            artifact.execution.transaction.to,
          data:
            artifact.execution.transaction.data ?? "0x",
          valueWei:
            artifact.execution.transaction.valueWei ?? "0"
        },
        controllerApproval.signature,
        {
          maxNativeValueWei: "1"
        }
      );

    if (observed.signTransactionCalls() !== 1) {
      throw new Error(
        `Authorized execution expected exactly one signTransaction call, observed ${observed.signTransactionCalls()}`
      );
    }

    artifact.verification.exact.signerCallCount = 1;

    const receipt =
      await guardedResult.response.wait();

    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `guarded Sepolia tx failed: ${guardedResult.transactionHash}`
      );
    }

    artifact.executionResult = {
      transactionHash:
        guardedResult.transactionHash,
      blockNumber:
        receipt.blockNumber.toString(),
      controller:
        guardedResult.controller,
      executor:
        wallet.address,
      signerCallCount:
        observed.signTransactionCalls(),
      fee:
        guardedResult.fee
    };

    persistLiveEvidence(
      loaded.path,
      artifact
    );

    console.log(
      JSON.stringify(
        {
          result:
            "LIVE VERIFIED DEMO PASSED",
          maliciousSimulatedSuccess:
            "BLOCKED by GuardedSigner; signTransaction calls=0",
          exactProofBackedExecution:
            "GuardedSigner ALLOW -> sign exact canonical envelope once -> broadcast",
          controller:
            guardedResult.controller,
          executor:
            wallet.address,
          signerCallCount:
            observed.signTransactionCalls(),
          executionTransactionHash:
            guardedResult.transactionHash,
          executionBlockNumber:
            receipt.blockNumber.toString()
        },
        null,
        2
      )
    );
  } finally {
    provider.destroy();
  }
}

main().catch(error => {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
});
