import express from "express";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  Interface,
  JsonRpcProvider,
  MaxUint256,
  getAddress,
  isAddress
} from "ethers";

import { z } from "zod";

import {
  analyzeTransaction
} from "./analyzer.js";

import {
  inspectOnchain
} from "./chain.js";

import {
  declaredIntentSchema
} from "./intent.js";

import {
  runIntentPreflight
} from "./intent-preflight.js";

import {
  runPreflight
} from "./preflight.js";

import {
  createConfiguredAuthorizationReader,
  runVerifiedPreflight
} from "./verified-preflight.js";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION
} from "./live-demo.js";

import type {
  LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  DEFAULT_LIVE_EVIDENCE_FILE,
  historicalEvidenceMatchesArtifacts
} from "./live-evidence.js";

import type {
  LiveJudgeEvidence
} from "./live-evidence.js";

import {
  loadLiveDeploymentArtifact
} from "./live-deployment.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  sanitizeRpcError
} from "./rpc-security.js";

const app = express();
const port = 8787;

const currentFile =
  fileURLToPath(import.meta.url);

const currentDir =
  path.dirname(currentFile);

app.use(
  express.json({
    limit: "64kb"
  })
);

app.use(
  express.static(
    path.join(
      currentDir,
      "../public"
    )
  )
);

const addressSchema =
  z.string()
    .min(1)
    .max(128)
    .refine(isAddress, "Invalid EVM address");

const uintStringSchema =
  z.string()
    .regex(/^\d+$/)
    .max(78);

const hexDataSchema =
  z.string()
    .regex(/^0x(?:[0-9a-fA-F]{2})*$/)
    .max(131074);

const transactionSchema =
  z.object({
    chain:
      z.string().min(1).max(64).optional(),
    from:
      addressSchema.optional(),
    to:
      addressSchema,
    data:
      hexDataSchema.optional(),
    valueWei:
      uintStringSchema.optional(),
    nonce:
      uintStringSchema.optional()
  }).strict();

const policySchema =
  z.object({
    maxNativeValueWei:
      uintStringSchema.optional(),
    allowedTargets:
      z.array(addressSchema).max(128).optional(),
    blockedTargets:
      z.array(addressSchema).max(128).optional(),
    requireKnownCalldata:
      z.boolean().optional()
  }).strict();

const requestSchema =
  z.object({
    transaction:
      transactionSchema,
    policy:
      policySchema.optional()
  }).strict();

const intentRequestSchema =
  z.object({
    intent:
      declaredIntentSchema,
    transaction:
      transactionSchema,
    policy:
      policySchema.optional()
  }).strict();

const verifiedRequestSchema =
  intentRequestSchema.extend({
    authorizationId:
      z.string().regex(
        /^0x[0-9a-fA-F]{64}$/,
        "authorizationId must be exactly 32 bytes"
      )
  }).strict();

function configuredRpcSecrets(): string[] {
  return [
    process.env.ETH_RPC_URL,
    process.env.SEPOLIA_RPC_URL,
    process.env.CREDITCOIN_RPC_URL
  ].filter((value): value is string => Boolean(value?.trim()));
}

function safeApiError(
  error: unknown,
  fallback: string
): string {
  const sanitized =
    sanitizeRpcError(
      error,
      configuredRpcSecrets()
    );

  return sanitized || fallback;
}

function readHistoricalArtifacts(): {
  deployment: NonNullable<ReturnType<typeof loadLiveDeploymentArtifact>>;
  artifact: LiveAuthorizationArtifact;
  evidence: LiveJudgeEvidence;
} | null {
  try {
    const artifactPath =
      process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
      DEFAULT_LIVE_DEMO_FILE;
    const evidencePath =
      process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
      DEFAULT_LIVE_EVIDENCE_FILE;

    if (!existsSync(artifactPath) || !existsSync(evidencePath)) {
      return null;
    }

    const deployment =
      loadLiveDeploymentArtifact();

    if (!deployment?.source || !deployment.semanticRegistry) {
      return null;
    }

    const artifact = JSON.parse(
      readFileSync(artifactPath, "utf8")
    ) as LiveAuthorizationArtifact;
    const evidence = JSON.parse(
      readFileSync(evidencePath, "utf8")
    ) as LiveJudgeEvidence;

    if (artifact.version !== LIVE_DEMO_ARTIFACT_VERSION) {
      return null;
    }

    return { deployment, artifact, evidence };
  } catch {
    return null;
  }
}

function historicalLiveEvidenceArtifactConsistentStatus(): boolean {
  const state = readHistoricalArtifacts();

  if (!state?.artifact.creditcoin) {
    return false;
  }

  return historicalEvidenceMatchesArtifacts({
    deployment: state.deployment,
    artifact: state.artifact,
    evidence: state.evidence,
    registryRecord: {
      commitment: state.artifact.source.commitment,
      sourceChainKey: state.artifact.creditcoin.sourceChainKey,
      sourceBlockNumber: state.artifact.creditcoin.sourceBlockNumber,
      transactionIndex: state.artifact.creditcoin.transactionIndex,
      validUntil: state.artifact.execution.declaredIntent.validUntil ?? "0"
    },
    requireVerifiedRecord: false
  });
}

async function historicalSemanticRegistryVerifiedStatus(): Promise<boolean> {
  const state = readHistoricalArtifacts();

  if (!state) {
    return false;
  }

  try {
    const record =
      await createConfiguredAuthorizationReader()
        .getAuthorization(
          state.artifact.source.authorizationId
        );

    if (!record) {
      return false;
    }

    return historicalEvidenceMatchesArtifacts({
      deployment: state.deployment,
      artifact: state.artifact,
      evidence: state.evidence,
      registryRecord: record
    });
  } catch {
    return false;
  }
}

async function authorizationChainWindowOpenStatus(): Promise<boolean> {
  const state = readHistoricalArtifacts();
  const declared = state?.artifact.execution.declaredIntent;

  if (
    !state ||
    !declared?.sender ||
    !declared.executionNonce ||
    !declared.validUntil
  ) {
    return false;
  }

  let provider: JsonRpcProvider | null = null;

  try {
    const network = resolveNetwork("sepolia");
    const endpoint = trustedRpcForEnforcement(network);

    provider = new JsonRpcProvider(
      endpoint.url,
      Number(network.chainId),
      { staticNetwork: true }
    );

    const [actualNetwork, block, pendingNonce] =
      await Promise.all([
        provider.getNetwork(),
        provider.getBlock("latest"),
        provider.getTransactionCount(
          getAddress(declared.sender),
          "pending"
        )
      ]);

    if (
      actualNetwork.chainId !== network.chainId ||
      !block
    ) {
      return false;
    }

    return (
      BigInt(block.timestamp) < BigInt(declared.validUntil) &&
      BigInt(pendingNonce) === BigInt(declared.executionNonce)
    );
  } catch {
    return false;
  } finally {
    provider?.destroy();
  }
}

app.get(
  "/api/health",
  async (_req, res) => {
    let deployment: ReturnType<typeof loadLiveDeploymentArtifact> = null;

    try {
      deployment =
        loadLiveDeploymentArtifact();
    } catch {
      deployment = null;
    }

    const historicalLiveEvidenceArtifactConsistent =
      historicalLiveEvidenceArtifactConsistentStatus();
    const historicalSemanticRegistryVerified =
      await historicalSemanticRegistryVerifiedStatus();
    const authorizationChainWindowOpen =
      historicalSemanticRegistryVerified
        ? await authorizationChainWindowOpenStatus()
        : false;

    res.json({
      ok: true,
      name: "AgentFirewall",
      build: "1.0.0-rc.6-agent-demo",
      baseline: "project-start-2026-09-07",
      standardPreflight: true,
      intentIntegrity: true,
      verifiedPreflightEndpoint: true,
      strongSigningBoundary: "GuardedSigner signer boundary",
      controllerApprovalRequiredByGuardedSigner: true,
      mcpAgentAdapter: true,
      mcpRawSignerExposed: false,
      feePolicyRequiredByGuardedSigner: true,
      controllerApprovalFeeBinding: "eip712-v2-fee-ceilings",
      nonceReservation: "in-process-sender-chain-nonce",
      secondaryExecutionRpcSupported: true,
      verifiedAuthorizationSemantics: "necessary-not-sufficient-local-deny-layer",
      verifiedEnforcementRequiresExplicitRpc: true,
      creditcoinRegistryConfigured:
        Boolean(
          deployment?.semanticRegistry?.address ||
          process.env.AGENTFIREWALL_REGISTRY_ADDRESS
        ),
      historicalLiveEvidenceArtifactConsistent,
      historicalSemanticRegistryVerified,
      authorizationChainWindowOpen,
      authorizationCurrentlyUsable: false,
      currentAuthorizationEvaluation:
        "not-evaluated: GuardedSigner requires a concrete execution request, fee envelope, fresh chain snapshot, and independent controller approval",
      historicalAuthorizationNote:
        "Bundled Sepolia/CC3 evidence is historical and locally artifact-consistent only. historicalSemanticRegistryVerified is true only after a configured Creditcoin RPC returns a verified record. authorizationChainWindowOpen is not an ALLOW verdict.",
      attestcoinProofGateImplemented: true,
      semanticAuthorizationRegistryImplemented: true,
      replayBoundExecutionNonce: true,
      authorizationExpiryUsesChainTime: true,
      executionPayloadCommitment: true,
      targetRuntimeCodeHashBinding: true,
      upgradeableProxyPolicy: "detected-common-proxies-fail-closed"
    });
  }
);

app.get(
  "/api/judge-demo",
  (_req, res) => {
    const state = readHistoricalArtifacts();

    if (!state) {
      res.status(404).json({
        error: "Live judge artifacts are not available"
      });
      return;
    }

    const { artifact, evidence } = state;
    const controller =
      evidence.controllerApproval?.controller ??
      artifact.controllerApproval?.controller ??
      null;
    const executor =
      evidence.controllerApproval?.executor ??
      artifact.controllerApproval?.executor ??
      artifact.execution.declaredIntent.sender ??
      null;
    const guarded = evidence.guardedSigner ?? null;
    const historicalArtifactConsistent =
      Boolean(
        historicalLiveEvidenceArtifactConsistentStatus() &&
        controller &&
        guarded &&
        evidence.execution?.transactionHash
      );

    res.json({
      version: "AgentFirewall.HistoricalEvidence.v2",
      proofKind: "historical-bundled-artifact",
      generatedAt: evidence.generatedAt,
      historicalArtifactConsistent,
      authorization: {
        authorizationId:
          evidence.authorization.authorizationId,
        commitment:
          evidence.authorization.commitment,
        sourceTransactionHash:
          evidence.source.transactionHash,
        sourceExplorer:
          evidence.source.explorerTransaction
      },
      attestation: {
        registryAddress:
          evidence.creditcoin.registryAddress,
        creditcoinTransactionHash:
          evidence.creditcoin.transactionHash,
        proofPreflightVerified:
          evidence.creditcoin.proofPreflightVerified,
        explorer:
          evidence.creditcoin.explorerTransaction
      },
      controller: {
        address: controller,
        executor,
        separated:
          Boolean(
            controller &&
            executor &&
            controller.toLowerCase() !== executor.toLowerCase()
          )
      },
      agent: {
        declaredIntent:
          artifact.execution.declaredIntent,
        canonicalCandidate:
          artifact.execution.transaction,
        mutatedCandidate:
          artifact.execution.mutatedTransaction
      },
      scenarios: {
        mutated: {
          simulation:
            evidence.firewall.mutatedExecutablePayload.simulation,
          decision:
            evidence.firewall.mutatedExecutablePayload.decision,
          criticalFindingCodes:
            evidence.firewall.mutatedExecutablePayload.criticalFindingCodes,
          signerCalled:
            guarded?.mutated.signerCalled ?? null,
          signerCallCount:
            guarded?.mutated.signerCallCount ?? null
        },
        canonical: {
          simulation:
            evidence.firewall.exactProofBackedPayload.simulation,
          decision:
            evidence.firewall.exactProofBackedPayload.decision,
          signerCalled:
            guarded?.canonical.signerCalled ?? null,
          signerCallCount:
            guarded?.canonical.signerCallCount ?? null,
          transactionHash:
            evidence.execution?.transactionHash ?? null,
          blockNumber:
            evidence.execution?.blockNumber ?? null,
          explorer:
            evidence.execution?.explorerTransaction ?? null
        }
      }
    });
  }
);

app.get(
  "/api/examples",
  (_req, res) => {
    const erc20 =
      new Interface([
        "function approve(address spender,uint256 amount)"
      ]);

    const token =
      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

    const spender =
      "0x1111111111111111111111111111111111111111";

    const sender =
      "0x5555555555555555555555555555555555555555";

    const limitedApproval =
      erc20.encodeFunctionData(
        "approve",
        [
          spender,
          1n
        ]
      );

    const dangerousApproval =
      erc20.encodeFunctionData(
        "approve",
        [
          spender,
          MaxUint256
        ]
      );

    res.json({
      dangerousApproval: {
        transaction: {
          chain: "ethereum",
          to: token,
          data: dangerousApproval,
          valueWei: "0"
        },
        policy: {
          requireKnownCalldata: true
        }
      },

      wethInspection: {
        transaction: {
          chain: "ethereum",
          to: token,
          data: "0x",
          valueWei: "0"
        }
      },

      intentIntegrity: {
        intent: {
          executionChainId: "1",
          sender,
          action: "erc20_approve",
          target: token,
          asset: {
            kind: "erc20",
            address: token
          },
          spender,
          amountRaw: "1",
          method: "approve(address,uint256)"
        },
        safeTransaction: {
          chain: "ethereum",
          from: sender,
          to: token,
          data: limitedApproval,
          valueWei: "0"
        },
        mutatedTransaction: {
          chain: "ethereum",
          from: sender,
          to: token,
          data: dangerousApproval,
          valueWei: "0"
        }
      }
    });
  }
);

app.post(
  "/api/analyze",
  (req, res) => {
    const parsed =
      requestSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: "Invalid request",
        details:
          parsed.error.flatten()
      });
      return;
    }

    try {
      res.json(
        analyzeTransaction(
          parsed.data.transaction,
          parsed.data.policy ?? {}
        )
      );
    } catch (error) {
      res.status(400).json({
        error:
          error instanceof Error
            ? safeApiError(error, "Analysis failed")
            : "Unknown error"
      });
    }
  }
);

app.post(
  "/api/inspect",
  async (req, res) => {
    const parsed =
      transactionSchema.safeParse(
        req.body?.transaction ?? req.body
      );

    if (!parsed.success) {
      res.status(400).json({
        error: "Invalid transaction",
        details:
          parsed.error.flatten()
      });
      return;
    }

    try {
      res.json(
        await inspectOnchain(
          parsed.data
        )
      );
    } catch (error) {
      res.status(502).json({
        error:
          error instanceof Error
            ? safeApiError(error, "RPC inspection failed")
            : "RPC inspection failed"
      });
    }
  }
);

app.post(
  "/api/preflight",
  async (req, res) => {
    const parsed =
      requestSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: "Invalid request",
        details:
          parsed.error.flatten()
      });
      return;
    }

    try {
      res.json(
        await runPreflight(
          parsed.data.transaction,
          parsed.data.policy ?? {}
        )
      );
    } catch (error) {
      res.status(502).json({
        error:
          error instanceof Error
            ? safeApiError(error, "Preflight failed")
            : "Preflight failed"
      });
    }
  }
);

app.post(
  "/api/intent-preflight",
  async (req, res) => {
    const parsed =
      intentRequestSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: "Invalid intent preflight request",
        details:
          parsed.error.flatten()
      });
      return;
    }

    try {
      res.json(
        await runIntentPreflight(
          parsed.data.intent,
          parsed.data.transaction,
          parsed.data.policy ?? {}
        )
      );
    } catch (error) {
      res.status(502).json({
        error:
          error instanceof Error
            ? safeApiError(error, "Intent preflight failed")
            : "Intent preflight failed"
      });
    }
  }
);

app.post(
  "/api/verified-preflight",
  async (req, res) => {
    const parsed =
      verifiedRequestSchema.safeParse(
        req.body
      );

    if (!parsed.success) {
      res.status(400).json({
        error:
          "Invalid verified preflight request",
        details:
          parsed.error.flatten()
      });
      return;
    }

    try {
      const reader =
        createConfiguredAuthorizationReader();

      res.json(
        await runVerifiedPreflight(
          parsed.data.authorizationId,
          parsed.data.intent,
          parsed.data.transaction,
          reader,
          parsed.data.policy ?? {}
        )
      );
    } catch (error) {
      res.status(502).json({
        error:
          error instanceof Error
            ? safeApiError(error, "Verified preflight failed")
            : "Verified preflight failed"
      });
    }
  }
);

app.listen(
  port,
  "127.0.0.1",
  () => {
    console.log(
      `AgentFirewall 1.0.0-rc.6 agent-demo build running at http://127.0.0.1:${port}`
    );
  }
);
