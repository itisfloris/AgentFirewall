import {
  readFileSync
} from "node:fs";

import {
  JsonRpcProvider,
  Wallet,
  getAddress,
  isAddress
} from "ethers";

import {
  McpServer
} from "@modelcontextprotocol/server";

import {
  serveStdio
} from "@modelcontextprotocol/server/stdio";

import * as z from "zod/v4";

import {
  GuardedSigner,
  GuardedSignerRejectedError,
  type FeeSafetyPolicy
} from "./guarded-signer.js";

import {
  declaredIntentSchema
} from "./intent.js";

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
  observeSigner
} from "./signer-observer.js";

import {
  createConfiguredAuthorizationReader,
  runVerifiedPreflight
} from "./verified-preflight.js";

const addressSchema = z.string().refine(
  value => isAddress(value),
  "invalid EVM address"
);

const uintStringSchema = z.string().regex(
  /^(0|[1-9][0-9]*)$/,
  "must be an unsigned decimal integer"
);

const transactionSchema = z.object({
  chain: z.string().min(1),
  from: addressSchema,
  to: addressSchema,
  data: z.string().regex(/^0x([0-9a-fA-F]{2})*$/).default("0x"),
  valueWei: uintStringSchema.default("0"),
  nonce: uintStringSchema
}).strict();

const proposalSchema = z.object({
  authorizationId: z.string().regex(
    /^0x[0-9a-fA-F]{64}$/,
    "authorizationId must be exactly 32 bytes"
  ),
  declaredIntent: declaredIntentSchema,
  candidateTransaction: transactionSchema
}).strict();

function textResult(
  value: unknown,
  isError = false
) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2)
      }
    ],
    ...(isError ? { isError: true } : {})
  };
}

function requiredEnv(
  name: string
): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function feePolicy(): FeeSafetyPolicy {
  return {
    maxGasLimit:
      requiredEnv("AGENTFIREWALL_MAX_GAS_LIMIT"),
    maxFeePerGasWei:
      requiredEnv("AGENTFIREWALL_MAX_FEE_PER_GAS_WEI"),
    maxPriorityFeePerGasWei:
      requiredEnv("AGENTFIREWALL_MAX_PRIORITY_FEE_PER_GAS_WEI"),
    maxTotalFeeWei:
      requiredEnv("AGENTFIREWALL_MAX_TOTAL_FEE_WEI")
  };
}

function liveArtifact(): LiveAuthorizationArtifact | null {
  try {
    const path =
      process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
      DEFAULT_LIVE_DEMO_FILE;
    const artifact = JSON.parse(
      readFileSync(path, "utf8")
    ) as LiveAuthorizationArtifact;

    return artifact.version === LIVE_DEMO_ARTIFACT_VERSION
      ? artifact
      : null;
  } catch {
    return null;
  }
}

function controllerApprovalFor(
  authorizationId: string
): {
  controller: string;
  signature: string;
} {
  const artifact = liveArtifact();
  const artifactMatches =
    artifact?.source.authorizationId.toLowerCase() ===
    authorizationId.toLowerCase();

  const controller =
    process.env.AGENTFIREWALL_TRUSTED_CONTROLLER?.trim() ||
    (artifactMatches
      ? artifact?.controllerApproval?.controller
      : undefined);
  const signature =
    process.env.AGENTFIREWALL_CONTROLLER_SIGNATURE?.trim() ||
    (artifactMatches
      ? artifact?.controllerApproval?.signature
      : undefined);

  if (!controller || !signature) {
    throw new Error(
      "No independent controller approval is configured for this authorization"
    );
  }

  return {
    controller: getAddress(controller),
    signature
  };
}

function buildServer(): McpServer {
  const server = new McpServer({
    name: "agentfirewall",
    version: "1.0.0-rc.6"
  });

  server.registerTool(
    "agentfirewall_check",
    {
      title: "Check an agent transaction against verified authorization",
      description:
        "Checks an AI agent's DeclaredIntent and candidate EVM transaction against Attestcoin/Creditcoin verified authorization. This tool never signs or broadcasts.",
      inputSchema: proposalSchema
    },
    async ({
      authorizationId,
      declaredIntent,
      candidateTransaction
    }) => {
      try {
        const reader =
          createConfiguredAuthorizationReader();
        const verdict =
          await runVerifiedPreflight(
            authorizationId,
            declaredIntent,
            candidateTransaction,
            reader
          );

        return textResult({
          decision: verdict.decision,
          simulation:
            verdict.onchain.simulation.ok
              ? "SUCCESS"
              : "FAILED",
          signerCalled: false,
          authorizationVerified:
            verdict.authorization.ok,
          findings:
            verdict.findings.map(finding => ({
              severity: finding.severity,
              code: finding.code,
              message: finding.message
            }))
        });
      } catch (error) {
        return textResult(
          {
            decision: "ERROR",
            signerCalled: false,
            error:
              error instanceof Error
                ? error.message
                : String(error)
          },
          true
        );
      }
    }
  );

  server.registerTool(
    "agentfirewall_execute",
    {
      title: "Execute an authorized Sepolia agent transaction",
      description:
        "Testnet-only guarded execution. The model supplies only authorization id, DeclaredIntent and candidate transaction. The executor key and controller approval remain inside the AgentFirewall process. BLOCK never reaches signTransaction().",
      inputSchema: proposalSchema
    },
    async ({
      authorizationId,
      declaredIntent,
      candidateTransaction
    }) => {
      if (
        process.env.AGENTFIREWALL_MCP_ENABLE_SEND !== "true"
      ) {
        return textResult(
          {
            decision: "BLOCK",
            signerCalled: false,
            reason:
              "Live MCP sending is disabled. Set AGENTFIREWALL_MCP_ENABLE_SEND=true only for the disposable Sepolia demo executor."
          },
          true
        );
      }

      const sepolia = resolveNetwork("sepolia");

      let candidateNetwork: ReturnType<typeof resolveNetwork>;

      try {
        candidateNetwork = resolveNetwork(
          candidateTransaction.chain
        );
      } catch {
        return textResult(
          {
            decision: "BLOCK",
            signerCalled: false,
            reason:
              `Unsupported candidate chain: ${candidateTransaction.chain}.`
          },
          true
        );
      }

      if (
        declaredIntent.executionChainId !==
          sepolia.chainId.toString() ||
        candidateNetwork.chainId !== sepolia.chainId
      ) {
        return textResult(
          {
            decision: "BLOCK",
            signerCalled: false,
            reason:
              "The MCP execution adapter is deliberately limited to Sepolia."
          },
          true
        );
      }

      let provider: JsonRpcProvider | null = null;

      try {
        const endpoint =
          trustedRpcForEnforcement(sepolia);
        provider = new JsonRpcProvider(
          endpoint.url,
          Number(sepolia.chainId),
          { staticNetwork: true }
        );
        const wallet = new Wallet(
          requiredEnv("AGENTFIREWALL_TESTNET_PRIVATE_KEY"),
          provider
        );

        if (
          getAddress(candidateTransaction.from) !==
          wallet.address
        ) {
          return textResult(
            {
              decision: "BLOCK",
              signerCalled: false,
              reason:
                `Candidate sender ${getAddress(candidateTransaction.from)} is not the configured executor ${wallet.address}.`
            },
            true
          );
        }

        if (
          !declaredIntent.executionNonce ||
          candidateTransaction.nonce !==
            declaredIntent.executionNonce
        ) {
          return textResult(
            {
              decision: "BLOCK",
              signerCalled: false,
              reason:
                "Candidate nonce must exactly match DeclaredIntent.executionNonce."
            },
            true
          );
        }

        const approval =
          controllerApprovalFor(authorizationId);
        const observed = observeSigner(wallet);
        const guardedSigner = new GuardedSigner(
          observed.signer,
          createConfiguredAuthorizationReader(),
          {
            trustedController:
              approval.controller,
            feePolicy: feePolicy(),
            rpcSourceLabel:
              endpoint.source
          }
        );

        try {
          const result =
            await guardedSigner.guardAndSendVerified(
              authorizationId,
              declaredIntent,
              {
                to:
                  candidateTransaction.to,
                data:
                  candidateTransaction.data,
                valueWei:
                  candidateTransaction.valueWei
              },
              approval.signature
            );

          return textResult({
            decision: "ALLOW",
            simulation: "SUCCESS",
            signerCalled: true,
            signerCallCount:
              observed.signTransactionCalls(),
            controller:
              result.controller,
            executor:
              wallet.address,
            transactionHash:
              result.transactionHash,
            fee:
              result.fee
          });
        } catch (error) {
          if (error instanceof GuardedSignerRejectedError) {
            return textResult(
              {
                decision: "BLOCK",
                signerCalled:
                  observed.signTransactionCalls() > 0,
                signerCallCount:
                  observed.signTransactionCalls(),
                rejectionCode:
                  error.code,
                findings:
                  error.verdict?.findings.map(finding => ({
                    severity: finding.severity,
                    code: finding.code,
                    message: finding.message
                  })) ?? []
              }
            );
          }

          throw error;
        }
      } catch (error) {
        return textResult(
          {
            decision: "ERROR",
            signerCalled: false,
            error:
              error instanceof Error
                ? error.message
                : String(error)
          },
          true
        );
      } finally {
        provider?.destroy();
      }
    }
  );

  return server;
}

await serveStdio(() => buildServer());
