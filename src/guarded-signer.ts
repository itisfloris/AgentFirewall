import {
  Transaction,
  getAddress,
  keccak256,
  toBeHex,
  type Provider,
  type TransactionRequest,
  type TransactionResponse
} from "ethers";

import type {
  SecurityPolicy,
  TransactionInput
} from "./analyzer.js";

import {
  inspectOnchainWithProvider
} from "./chain.js";

import {
  controllerApprovalTypedData,
  controllerApprovalTypedDataV2,
  verifyControllerApprovalV2,
  type ControllerApprovalMessage
} from "./controller-approval.js";

import {
  GuardedSignerRejectedError
} from "./guarded-signer-error.js";

import {
  enforceFeeSafety,
  normalizeFeeSafetyPolicy,
  snapshotSecurityPolicy,
  type FeeSafetyPolicy,
  type GuardedSignerOptions
} from "./guarded-signer-policy.js";

import {
  immutablePopulatedTransaction,
  normalizeRequestedExecution,
  type GuardedExecutionInput
} from "./guarded-signer-transaction.js";

import {
  declaredIntentSchema,
  type DeclaredIntent
} from "./intent.js";

import {
  resolveNetwork
} from "./networks.js";

import {
  sanitizeRpcError
} from "./rpc-security.js";

import {
  reserveExecutionNonce
} from "./nonce-reservation.js";

import type {
  TransactionSignerBoundary
} from "./signer-boundary.js";

import {
  runVerifiedPreflight,
  type VerifiedAuthorizationReader
} from "./verified-preflight.js";

export {
  GuardedSignerRejectedError
} from "./guarded-signer-error.js";

export {
  enforceFeeSafety,
  type FeeSafetyPolicy,
  type GuardedSignerOptions
} from "./guarded-signer-policy.js";

export type {
  GuardedExecutionInput
} from "./guarded-signer-transaction.js";

export {
  ExternalTransactionSignerAdapter
} from "./signer-boundary.js";

export type {
  TransactionSignerBoundary
} from "./signer-boundary.js";

export type GuardedSendResult = {
  verdict: Awaited<ReturnType<typeof runVerifiedPreflight>>;
  transaction: Readonly<TransactionRequest>;
  transactionHash: string;
  response: TransactionResponse;
  controller: string;
  fee: {
    gasLimit: string;
    maxUnitFeeWei: string;
    worstCaseTotalFeeWei: string;
  };
};

type RpcSendProvider = Provider & {
  send(method: string, params: Array<unknown>): Promise<unknown>;
};

function hasRpcSend(
  provider: Provider
): provider is RpcSendProvider {
  return typeof (provider as Partial<RpcSendProvider>).send === "function";
}

export class GuardedSigner {
  private readonly trustedController: string;
  private readonly feePolicy: Readonly<FeeSafetyPolicy>;
  private readonly rpcSourceLabel: string;
  private readonly secondaryExecutionProvider?: Provider;

  constructor(
    private readonly signer: TransactionSignerBoundary,
    private readonly reader: VerifiedAuthorizationReader,
    options: GuardedSignerOptions
  ) {
    this.trustedController =
      getAddress(options.trustedController);
    this.feePolicy =
      normalizeFeeSafetyPolicy(options.feePolicy);
    this.rpcSourceLabel =
      options.rpcSourceLabel?.trim() ||
      "guarded-signer-explicit-provider";
    this.secondaryExecutionProvider =
      options.secondaryExecutionProvider;
  }

  async guardAndSendVerified(
    authorizationId: string,
    declaredIntent: DeclaredIntent,
    requestedTransaction: GuardedExecutionInput,
    controllerSignature: string,
    policy: SecurityPolicy = {}
  ): Promise<GuardedSendResult> {
    try {
      return await this.guardAndSendVerifiedInner(
        authorizationId,
        declaredIntent,
        requestedTransaction,
        controllerSignature,
        policy
      );
    } catch (error) {
      if (error instanceof GuardedSignerRejectedError) {
        throw error;
      }

      throw new GuardedSignerRejectedError(
        `guarded send failed: ${sanitizeRpcError(error)}`,
        "GUARDED_SIGNER_DEPENDENCY_FAILED"
      );
    }
  }

  private async guardAndSendVerifiedInner(
    authorizationId: string,
    declaredIntent: DeclaredIntent,
    requestedTransaction: GuardedExecutionInput,
    controllerSignature: string,
    policy: SecurityPolicy = {}
  ): Promise<GuardedSendResult> {
    const stableDeclaredIntent =
      declaredIntentSchema.parse(declaredIntent) as DeclaredIntent;
    const stablePolicy = snapshotSecurityPolicy(policy);
    const requested =
      normalizeRequestedExecution(
        requestedTransaction
      );

    const provider = this.signer.provider;

    if (!provider || !hasRpcSend(provider)) {
      throw new GuardedSignerRejectedError(
        "signer needs a JSON-RPC provider",
        "TRUSTED_EXECUTION_PROVIDER_REQUIRED"
      );
    }

    const sender = getAddress(
      await this.signer.getAddress()
    );

    if (sender === this.trustedController) {
      throw new GuardedSignerRejectedError(
        "controller and executor must differ",
        "AUTHORITY_SEPARATION_REQUIRED"
      );
    }

    const network = await provider.getNetwork();
    const resolvedNetwork =
      resolveNetwork(network.chainId.toString());

    if (resolvedNetwork.chainId !== network.chainId) {
      throw new GuardedSignerRejectedError(
        "Signer provider chain is unsupported",
        "UNSUPPORTED_EXECUTION_CHAIN"
      );
    }

    const pendingNonce =
      await provider.getTransactionCount(
        sender,
        "pending"
      );

    const releaseNonce =
      reserveExecutionNonce(
        network.chainId,
        sender,
        pendingNonce
      );

    try {
    const to = requested.to;
    const data = requested.data;
    const value = requested.value;

    const populated =
      await this.signer.populateTransaction({
        from: sender,
        to,
        data,
        value,
        nonce: pendingNonce,
        chainId: network.chainId
      });

    const canonical =
      immutablePopulatedTransaction(
        populated,
        {
          sender,
          chainId: network.chainId,
          nonce: pendingNonce,
          to,
          data,
          value
        }
      );

    const fee = enforceFeeSafety(
      canonical,
      this.feePolicy
    );

    const firewallTransaction: TransactionInput = {
      chain: network.chainId.toString(),
      from: sender,
      to,
      data,
      valueWei: value.toString(),
      nonce: pendingNonce.toString()
    };

    const verdict =
      await runVerifiedPreflight(
        authorizationId,
        stableDeclaredIntent,
        firewallTransaction,
        this.reader,
        stablePolicy,
        transaction =>
          inspectOnchainWithProvider(
            transaction,
            resolvedNetwork,
            provider,
            this.rpcSourceLabel
          )
      );

    if (verdict.decision !== "ALLOW") {
      throw new GuardedSignerRejectedError(
        `blocked: ${verdict.decision}`,
        "VERIFIED_PREFLIGHT_BLOCKED",
        verdict
      );
    }

    const record =
      verdict.authorization.registryRecord;

    if (
      !record ||
      !record.registryAddress ||
      !record.commitment
    ) {
      throw new GuardedSignerRejectedError(
        "missing registry record",
        "VERIFIED_RECORD_INCOMPLETE",
        verdict
      );
    }

    if (
      record.registryTrustAnchorsVerified !== true ||
      record.registryRuntimeCodeHashVerified !== true
    ) {
      throw new GuardedSignerRejectedError(
        "registry identity was not verified",
        "REGISTRY_IDENTITY_UNVERIFIED",
        verdict
      );
    }

    const controllerMessage: ControllerApprovalMessage = {
      authorizationId,
      commitment: record.commitment,
      executor: sender,
      executionChainId:
        network.chainId.toString(),
      executionNonce:
        pendingNonce.toString(),
      validUntil:
        record.validUntil,
      registryAddress:
        record.registryAddress,
      sourceChainKey:
        record.sourceChainKey
    };

    const controller =
      verifyControllerApprovalV2(
        this.trustedController,
        controllerMessage,
        this.feePolicy,
        controllerSignature
      );

    const networkBeforeSign =
      await provider.getNetwork();
    const [nonceBeforeSign, latestBeforeSign] =
      await Promise.all([
        provider.getTransactionCount(
          sender,
          "pending"
        ),
        provider.getBlock("latest")
      ]);

    if (networkBeforeSign.chainId !== network.chainId) {
      throw new GuardedSignerRejectedError(
        "chain changed before signing",
        "CHAIN_CHANGED_BEFORE_SIGN",
        verdict
      );
    }

    if (nonceBeforeSign !== pendingNonce) {
      throw new GuardedSignerRejectedError(
        `nonce changed: ${pendingNonce} -> ${nonceBeforeSign}`,
        "NONCE_CHANGED_BEFORE_SIGN",
        verdict
      );
    }

    if (!latestBeforeSign?.hash) {
      throw new GuardedSignerRejectedError(
        "pre-sign block is unavailable",
        "PRESIGN_BLOCK_UNAVAILABLE",
        verdict
      );
    }

    if (
      BigInt(latestBeforeSign.timestamp) >=
      BigInt(record.validUntil)
    ) {
      throw new GuardedSignerRejectedError(
        `authorization expired at ${record.validUntil}`,
        "AUTHORIZATION_EXPIRED_BEFORE_SIGN",
        verdict
      );
    }

    const codeBeforeSign =
      await provider.send(
        "eth_getCode",
        [to, toBeHex(latestBeforeSign.number)]
      );

    if (typeof codeBeforeSign !== "string") {
      throw new GuardedSignerRejectedError(
        "bad pre-sign bytecode response",
        "PRESIGN_CODE_UNAVAILABLE",
        verdict
      );
    }

    const confirmedBeforeSign =
      await provider.getBlock(latestBeforeSign.number);

    if (
      !confirmedBeforeSign?.hash ||
      confirmedBeforeSign.hash.toLowerCase() !==
        latestBeforeSign.hash.toLowerCase()
    ) {
      throw new GuardedSignerRejectedError(
        `block ${latestBeforeSign.number} changed during recheck`,
        "PRESIGN_BLOCK_CHANGED",
        verdict
      );
    }

    if (
      keccak256(codeBeforeSign).toLowerCase() !==
      verdict.onchain.destination.codeHash.toLowerCase()
    ) {
      throw new GuardedSignerRejectedError(
        "target code changed before signing",
        "TARGET_CODE_CHANGED_BEFORE_SIGN",
        verdict
      );
    }

    const secondary =
      this.secondaryExecutionProvider;

    if (secondary) {
      if (!hasRpcSend(secondary)) {
        throw new GuardedSignerRejectedError(
          "secondary execution provider needs JSON-RPC send support",
          "SECONDARY_RPC_INVALID",
          verdict
        );
      }

      const secondaryNetwork =
        await secondary.getNetwork();
      const [
        secondaryNonce,
        secondaryBlock,
        secondaryCode
      ] = await Promise.all([
        secondary.getTransactionCount(sender, "pending"),
        secondary.getBlock(latestBeforeSign.number),
        secondary.send(
          "eth_getCode",
          [to, toBeHex(latestBeforeSign.number)]
        )
      ]);

      if (
        secondaryNetwork.chainId !== network.chainId ||
        secondaryNonce !== pendingNonce ||
        !secondaryBlock?.hash ||
        secondaryBlock.hash.toLowerCase() !== latestBeforeSign.hash.toLowerCase() ||
        typeof secondaryCode !== "string" ||
        keccak256(secondaryCode).toLowerCase() !==
          verdict.onchain.destination.codeHash.toLowerCase()
      ) {
        throw new GuardedSignerRejectedError(
          "secondary RPC disagreed on chain, nonce, block, or target code",
          "SECONDARY_RPC_MISMATCH",
          verdict
        );
      }
    }

    const expectedUnsigned =
      Transaction.from({
        type: canonical.type ?? undefined,
        to:
          canonical.to === null ||
          canonical.to === undefined
            ? null
            : String(canonical.to),
        data:
          canonical.data === null ||
          canonical.data === undefined
            ? "0x"
            : String(canonical.data),
        value: canonical.value ?? 0n,
        nonce:
          canonical.nonce === null ||
          canonical.nonce === undefined
            ? undefined
            : Number(canonical.nonce),
        chainId: canonical.chainId ?? 0n,
        gasLimit: canonical.gasLimit ?? 0n,
        gasPrice: canonical.gasPrice ?? undefined,
        maxFeePerGas:
          canonical.maxFeePerGas ?? undefined,
        maxPriorityFeePerGas:
          canonical.maxPriorityFeePerGas ?? undefined
      }).unsignedSerialized;

    const signedRaw =
      await this.signer.signTransaction(
        canonical
      );

    const signed =
      Transaction.from(signedRaw);

    if (
      signed.unsignedSerialized !==
      expectedUnsigned
    ) {
      throw new GuardedSignerRejectedError(
        "signer returned a different transaction",
        "SIGNED_TRANSACTION_MISMATCH",
        verdict
      );
    }

    if (
      !signed.from ||
      getAddress(signed.from) !== sender
    ) {
      throw new GuardedSignerRejectedError(
        "signed transaction has the wrong sender",
        "SIGNED_SENDER_MISMATCH",
        verdict
      );
    }

    const expectedTransactionHash = signed.hash;

    if (!expectedTransactionHash) {
      throw new GuardedSignerRejectedError(
        "signed transaction has no hash",
        "SIGNED_TRANSACTION_HASH_UNAVAILABLE",
        verdict
      );
    }

    const response =
      await provider.broadcastTransaction(
        signedRaw
      );

    if (
      response.hash.toLowerCase() !==
      expectedTransactionHash.toLowerCase()
    ) {
      throw new GuardedSignerRejectedError(
        `broadcast hash mismatch: ${response.hash}`,
        "BROADCAST_HASH_MISMATCH",
        verdict
      );
    }

    return {
      verdict,
      transaction: canonical,
      transactionHash: response.hash,
      response,
      controller,
      fee: {
        gasLimit:
          fee.gasLimit.toString(),
        maxUnitFeeWei:
          fee.maxUnitFeeWei.toString(),
        worstCaseTotalFeeWei:
          fee.worstCaseTotalFeeWei.toString()
      }
    };
    } finally {
      releaseNonce();
    }
  }
}

export {
  controllerApprovalTypedData,
  controllerApprovalTypedDataV2
};
