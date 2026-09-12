import {
  ZeroAddress,
  getAddress,
  isHexString
} from "ethers";

import type {
  TransactionInput
} from "./analyzer.js";

import type {
  DeclaredIntent
} from "./intent.js";

import type {
  ControllerApprovalMessage
} from "./controller-approval.js";

import {
  resolveNetwork
} from "./networks.js";

import type { FeeSafetyPolicy } from "./guarded-signer-policy.js";

export const LIVE_DEMO_ARTIFACT_VERSION =
  "AgentFirewall.LiveAuthorization.v1";

export const DEFAULT_LIVE_DEMO_FILE =
  "build/live-authorization.json";

export type NativeSourceAuthorization = {
  executionChainId: string;
  sender: string;
  executionNonce: string;
  validUntil: string;
  actionCode: number;
  target: string;
  targetCodeHash: string;
  asset: string;
  counterpartyA: string;
  counterpartyB: string;
  amountOrFlag: string;
};

export type LiveAuthorizationArtifact = {
  version: typeof LIVE_DEMO_ARTIFACT_VERSION;
  createdAt: string;
  build?: {
    sourceId?: string;
    sourceKind?: "git" | "standalone-sha256";
    sourceCommit?: string;
    sourceTreeClean?: boolean;
  };
  source: {
    network: "sepolia";
    chainId: string;
    authorizationSource: string;
    transactionHash: string;
    blockNumber: string;
    authorizationId: string;
    commitment: string;
    sourceAuthorizationNonce: string;
    transactionIndex?: string;
  };
  execution: {
    declaredIntent: DeclaredIntent;
    transaction: TransactionInput;
    mutatedTransaction: TransactionInput;
  };
  creditcoin?: {
    registryAddress: string;
    transactionHash: string;
    blockNumber: string;
    sourceChainKey: string;
    sourceBlockNumber: string;
    transactionIndex: string;
    transactionKey: string;
    provenTransactionHash: string;
    proofPreflightVerified?: boolean;
  };
  verification?: {
    generatedAt: string;
    mutated: {
      simulationOk: boolean;
      decision: string;
      criticalFindingCodes: string[];
      signerCallCount?: number;
    };
    exact: {
      simulationOk: boolean;
      decision: string;
      criticalFindingCodes: string[];
      signerCallCount?: number;
    };
  };
  controllerApproval?: {
    generatedAt: string;
    controller: string;
    executor: string;
    signature: string;
    message: ControllerApprovalMessage;
    version?: "1" | "2";
    feePolicy?: FeeSafetyPolicy;
  };
  executionResult?: {
    transactionHash: string;
    blockNumber: string;
    controller?: string;
    executor?: string;
    signerCallCount?: number;
    fee?: {
      gasLimit: string;
      maxUnitFeeWei: string;
      worstCaseTotalFeeWei: string;
    };
  };
};

function uint(
  value: bigint | number | string,
  field: string
): bigint {
  let parsed: bigint;

  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(
      `${field} must be an unsigned integer`
    );
  }

  if (parsed < 0n) {
    throw new Error(
      `${field} must be an unsigned integer`
    );
  }

  return parsed;
}

function bytes32(
  value: string,
  field: string
): string {
  if (!isHexString(value, 32)) {
    throw new Error(
      `${field} must be exactly 32 bytes`
    );
  }

  if (
    value.toLowerCase() ===
    `0x${"00".repeat(32)}`
  ) {
    throw new Error(
      `${field} must not be zero`
    );
  }

  return value.toLowerCase();
}

function mutationRecipient(
  target: string
): string {
  const candidateA =
    getAddress(
      "0x1111111111111111111111111111111111111111"
    );

  if (candidateA !== target) {
    return candidateA;
  }

  return getAddress(
    "0x2222222222222222222222222222222222222222"
  );
}

export function buildNativeLiveDemoPlan(
  input: {
    sender: string;
    recipient: string;
    currentSepoliaNonce: bigint | number | string;
    targetCodeHash: string;
    nowSeconds: bigint | number | string;
    validitySeconds?: bigint | number | string;
    amountWei?: bigint | number | string;
  }
): {
  authorization: NativeSourceAuthorization;
  declaredIntent: DeclaredIntent;
  transaction: TransactionInput;
  mutatedTransaction: TransactionInput;
} {
  const sepolia =
    resolveNetwork("sepolia");

  const sender =
    getAddress(input.sender);
  const recipient =
    getAddress(input.recipient);

  const currentNonce =
    uint(
      input.currentSepoliaNonce,
      "currentSepoliaNonce"
    );

  const now =
    uint(
      input.nowSeconds,
      "nowSeconds"
    );

  const validity =
    uint(
      input.validitySeconds ?? 3600n,
      "validitySeconds"
    );

  if (validity < 1200n) {
    throw new Error(
      "validitySeconds must be at least 1200"
    );
  }

  if (validity > 86400n) {
    throw new Error(
      "validitySeconds must not exceed 86400 seconds for the submission demo"
    );
  }

  const amount =
    uint(
      input.amountWei ?? 1n,
      "amountWei"
    );

  if (amount === 0n) {
    throw new Error(
      "amountWei must be greater than zero"
    );
  }

  const targetCodeHash =
    bytes32(
      input.targetCodeHash,
      "targetCodeHash"
    );

  const executionNonce =
    currentNonce + 1n;

  const validUntil =
    now + validity;

  const declaredIntent: DeclaredIntent = {
    executionChainId:
      sepolia.chainId.toString(),
    sender,
    executionNonce:
      executionNonce.toString(),
    validUntil:
      validUntil.toString(),
    targetCodeHash,
    action: "native_transfer",
    target: recipient,
    asset: {
      kind: "native"
    },
    recipient,
    amountRaw:
      amount.toString(),
    method: "native_transfer"
  };

  const transaction: TransactionInput = {
    chain: "sepolia",
    from: sender,
    to: recipient,
    nonce:
      executionNonce.toString(),
    data: "0x",
    valueWei:
      amount.toString()
  };

  const mutatedTransaction: TransactionInput = {
    ...transaction,
    to:
      mutationRecipient(recipient)
  };

  return {
    authorization: {
      executionChainId:
        sepolia.chainId.toString(),
      sender,
      executionNonce:
        executionNonce.toString(),
      validUntil:
        validUntil.toString(),
      actionCode: 1,
      target: recipient,
      targetCodeHash,
      asset: ZeroAddress,
      counterpartyA: recipient,
      counterpartyB: ZeroAddress,
      amountOrFlag:
        amount.toString()
    },
    declaredIntent,
    transaction,
    mutatedTransaction
  };
}
