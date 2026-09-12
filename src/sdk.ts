import { isAddress } from "ethers";
import { z } from "zod";

import type {
  ActualEffect,
  DeclaredIntent,
  IntegrityFinding
} from "./intent.js";

import type {
  AuthorizationIntegrity
} from "./verified-preflight.js";

import {
  sanitizeRpcError
} from "./rpc-security.js";

export type FirewallTransaction = {
  chain?: string;
  from?: string;
  to: string;
  data?: string;
  valueWei?: string;
  nonce?: string;
};

export type FirewallPolicy = {
  maxNativeValueWei?: string;
  allowedTargets?: string[];
  blockedTargets?: string[];
  requireKnownCalldata?: boolean;
};

export type FirewallFinding = {
  severity: "info" | "medium" | "high" | "critical";
  code: string;
  message: string;
};

export type FirewallVerdict = {
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  risk: "low" | "medium" | "high" | "critical";
  score: number;
  transactionSummary: string;
  intent: string;
  decoded: {
    method: string | null;
    arguments: string[];
  };
  findings: FirewallFinding[];
  onchain: {
    network: {
      key?: string;
      name: string;
      chainId: string;
      blockNumber: number;
      blockHash: string;
      timestamp: number;
    };
    destination: {
      address: string;
      kind: string;
      balanceWei: string;
      bytecodeBytes: number;
      codeHash: string;
      proxy?: {
        assessment: "not-detected" | "detected" | "unknown";
        kind: string;
      };
    };
    simulation:
      | { ok: true; result: string }
      | { ok: false; error: string };
    gasEstimate:
      | { ok: true; gas: string; advisory?: true }
      | { ok: false; error: string; advisory?: true };
    rpcSource: string;
  };
};

export type IntentFirewallVerdict =
  FirewallVerdict & {
    declaredIntent: DeclaredIntent;
    actualEffect: ActualEffect;
    integrity: {
      ok: boolean;
      decision: "ALLOW" | "BLOCK";
      findings: IntegrityFinding[];
    };
  };

export type VerifiedIntentFirewallVerdict =
  IntentFirewallVerdict & {
    authorization: AuthorizationIntegrity;
  };

const bytes32Schema =
  z.string().regex(/^0x[0-9a-fA-F]{64}$/);

const uintStringSchema =
  z.string().regex(/^\d+$/).max(78);

const evmAddressSchema =
  z.string().max(128).refine(isAddress, "Invalid EVM address");

const findingSchema = z.object({
  severity: z.enum(["info", "medium", "high", "critical"]),
  code: z.string().min(1).max(128),
  message: z.string().min(1).max(4096)
});

const firewallVerdictSchema = z.object({
  decision: z.enum(["ALLOW", "REVIEW", "BLOCK"]),
  risk: z.enum(["low", "medium", "high", "critical"]),
  score: z.number().finite().min(0).max(100),
  transactionSummary: z.string().max(8192),
  intent: z.string().max(8192),
  decoded: z.object({
    method: z.string().nullable(),
    arguments: z.array(z.string()).max(64)
  }),
  findings: z.array(findingSchema).max(256),
  onchain: z.object({
    network: z.object({
      key: z.string().optional(),
      name: z.string().min(1).max(128),
      chainId: z.string().regex(/^\d+$/),
      blockNumber: z.number().int().nonnegative(),
      blockHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
      timestamp: z.number().int().nonnegative()
    }),
    destination: z.object({
      address: z.string().min(1).max(128),
      kind: z.string().min(1).max(128),
      balanceWei: z.string().regex(/^\d+$/),
      bytecodeBytes: z.number().int().nonnegative(),
      codeHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
      proxy: z.object({
        assessment: z.enum(["not-detected", "detected", "unknown"]),
        kind: z.string().min(1).max(64)
      }).passthrough().optional()
    }),
    simulation: z.union([
      z.object({
        ok: z.literal(true),
        result: z.string().max(131072)
      }),
      z.object({
        ok: z.literal(false),
        error: z.string().max(8192)
      })
    ]),
    gasEstimate: z.union([
      z.object({
        ok: z.literal(true),
        gas: z.string().regex(/^\d+$/),
        advisory: z.literal(true).optional()
      }),
      z.object({
        ok: z.literal(false),
        error: z.string().max(8192),
        advisory: z.literal(true).optional()
      })
    ]),
    rpcSource: z.string().min(1).max(256)
  })
}).passthrough();

const intentVerdictSchema = firewallVerdictSchema.extend({
  declaredIntent: z.unknown(),
  actualEffect: z.unknown(),
  integrity: z.object({
    ok: z.boolean(),
    decision: z.enum(["ALLOW", "BLOCK"]),
    findings: z.array(findingSchema).max(256)
  }).passthrough()
}).passthrough();

const verifiedVerdictSchema = intentVerdictSchema.extend({
  authorization: z.object({
    ok: z.boolean(),
    decision: z.enum(["ALLOW", "BLOCK"]),
    authorizationId: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    registryRecord: z.object({
      authorizationId: bytes32Schema,
      commitment: bytes32Schema,
      verified: z.boolean(),
      sourceChainKey: uintStringSchema,
      sourceBlockNumber: uintStringSchema,
      transactionIndex: uintStringSchema,
      validUntil: uintStringSchema,
      registryAddress: evmAddressSchema,
      creditcoinChainId: uintStringSchema,
      rpcSource: z.string().min(1).max(256),
      registryTrustAnchorsVerified: z.boolean(),
      registryRuntimeCodeHashVerified: z.boolean(),
      registrySnapshotBlockNumber: uintStringSchema,
      registrySnapshotBlockHash: bytes32Schema
    }).passthrough().nullable(),
    declaredCommitment: bytes32Schema.nullable(),
    actualCommitment: bytes32Schema.nullable(),
    actualTargetCodeHash: bytes32Schema.nullable(),
    findings: z.array(findingSchema).max(256)
  }).passthrough()
}).superRefine((value, context) => {
  if (value.decision !== "ALLOW") {
    return;
  }

  const record = value.authorization.registryRecord;

  if (
    value.integrity.ok !== true ||
    value.integrity.decision !== "ALLOW" ||
    value.integrity.findings.length !== 0 ||
    value.authorization.ok !== true ||
    value.authorization.decision !== "ALLOW" ||
    value.authorization.findings.length !== 0 ||
    record?.verified !== true ||
    record.registryTrustAnchorsVerified !== true ||
    record.registryRuntimeCodeHashVerified !== true ||
    !value.authorization.declaredCommitment ||
    !value.authorization.actualCommitment ||
    !value.authorization.actualTargetCodeHash ||
    value.authorization.declaredCommitment.toLowerCase() !==
      value.authorization.actualCommitment.toLowerCase() ||
    record.commitment.toLowerCase() !==
      value.authorization.actualCommitment.toLowerCase() ||
    value.onchain.destination.proxy?.assessment !== "not-detected"
  ) {
    context.addIssue({
      code: "custom",
      message:
        "Malformed ALLOW response: verified authorization/integrity invariants are incomplete"
    });
  }
});

export class FirewallRejectedError extends Error {
  constructor(
    public readonly verdict: FirewallVerdict
  ) {
    super(
      `AgentFirewall rejected transaction: ${verdict.decision} ${verdict.score}/100`
    );
    this.name = "FirewallRejectedError";
  }
}

export class AgentFirewallClient {
  private readonly normalizedBaseUrl: string;

  constructor(
    baseUrl = "http://127.0.0.1:8787",
    private readonly timeoutMs = 8000
  ) {
    const parsed = new URL(baseUrl);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      throw new Error(
        "AgentFirewall HTTP client supports only http/https URLs"
      );
    }

    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 120000
    ) {
      throw new Error(
        "AgentFirewall HTTP timeout must be between 100 and 120000 ms"
      );
    }

    this.normalizedBaseUrl =
      parsed.toString().replace(/\/$/, "");
  }

  private assertGuardTransport(): void {
    const parsed =
      new URL(this.normalizedBaseUrl);
    const loopback =
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "localhost" ||
      parsed.hostname === "[::1]" ||
      parsed.hostname === "::1";

    if (
      parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" && loopback)
    ) {
      throw new Error(
        "guard endpoint must use HTTPS (or loopback HTTP)"
      );
    }
  }

  private async post<T>(
    path: string,
    body: unknown,
    schema: z.ZodType<T>
  ): Promise<T> {
    const controller =
      new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.timeoutMs
    );

    try {
      const response = await fetch(
        `${this.normalizedBaseUrl}${path}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body),
          signal: controller.signal
        }
      );

      const responseText = await response.text();

      if (responseText.length > 524288) {
        throw new Error(
          `AgentFirewall HTTP ${response.status} response exceeds the 512 KiB client safety bound`
        );
      }

      let responseBody: unknown;

      try {
        responseBody = JSON.parse(responseText);
      } catch {
        throw new Error(
          `AgentFirewall HTTP ${response.status} returned non-JSON data`
        );
      }

      if (!response.ok) {
        throw new Error(
          `AgentFirewall HTTP ${response.status}: request rejected`
        );
      }

      const parsed = schema.safeParse(
        responseBody
      );

      if (!parsed.success) {
        throw new Error(
          `AgentFirewall returned a malformed response for ${path}`
        );
      }

      return parsed.data;
    } catch (error) {
      if (
        error instanceof Error &&
        error.name === "AbortError"
      ) {
        throw new Error(
          `AgentFirewall request timed out after ${this.timeoutMs} ms`
        );
      }

      throw new Error(
        sanitizeRpcError(
          error,
          [this.normalizedBaseUrl]
        )
      );
    } finally {
      clearTimeout(timer);
    }
  }

  async preflight(
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<FirewallVerdict> {
    return this.post(
      "/api/preflight",
      { transaction, policy },
      firewallVerdictSchema as z.ZodType<FirewallVerdict>
    );
  }

  async guard(
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<FirewallVerdict> {
    this.assertGuardTransport();
    const verdict = await this.preflight(
      transaction,
      policy
    );

    if (verdict.decision !== "ALLOW") {
      throw new FirewallRejectedError(
        verdict
      );
    }

    return verdict;
  }

  async intentPreflight(
    declaredIntent: DeclaredIntent,
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<IntentFirewallVerdict> {
    return this.post(
      "/api/intent-preflight",
      {
        intent: declaredIntent,
        transaction,
        policy
      },
      intentVerdictSchema as z.ZodType<IntentFirewallVerdict>
    );
  }

  async guardIntent(
    declaredIntent: DeclaredIntent,
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<IntentFirewallVerdict> {
    this.assertGuardTransport();
    const verdict =
      await this.intentPreflight(
        declaredIntent,
        transaction,
        policy
      );

    if (verdict.decision !== "ALLOW") {
      throw new FirewallRejectedError(
        verdict
      );
    }

    return verdict;
  }

  async verifiedPreflight(
    authorizationId: string,
    declaredIntent: DeclaredIntent,
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<VerifiedIntentFirewallVerdict> {
    return this.post(
      "/api/verified-preflight",
      {
        authorizationId,
        intent: declaredIntent,
        transaction,
        policy
      },
      verifiedVerdictSchema as z.ZodType<VerifiedIntentFirewallVerdict>
    );
  }

  async guardVerified(
    authorizationId: string,
    declaredIntent: DeclaredIntent,
    transaction: FirewallTransaction,
    policy: FirewallPolicy = {}
  ): Promise<VerifiedIntentFirewallVerdict> {
    this.assertGuardTransport();
    const verdict =
      await this.verifiedPreflight(
        authorizationId,
        declaredIntent,
        transaction,
        policy
      );

    if (verdict.decision !== "ALLOW") {
      throw new FirewallRejectedError(
        verdict
      );
    }

    return verdict;
  }
}

export type {
  DeclaredIntent
} from "./intent.js";

export {
  GuardedSigner,
  GuardedSignerRejectedError,
  ExternalTransactionSignerAdapter,
  enforceFeeSafety,
  type FeeSafetyPolicy,
  type GuardedExecutionInput,
  type GuardedSignerOptions,
  type TransactionSignerBoundary
} from "./guarded-signer.js";

export {
  controllerApprovalTypedData,
  controllerApprovalTypedDataV2,
  verifyControllerApproval,
  verifyControllerApprovalV2,
  type ControllerApprovalMessage,
  type ControllerFeeBinding
} from "./controller-approval.js";
