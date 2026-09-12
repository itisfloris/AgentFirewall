import {
  getAddress,
  isAddress,
  type TransactionRequest
} from "ethers";

import {
  GuardedSignerRejectedError
} from "./guarded-signer-error.js";

export type GuardedExecutionInput = {
  to: string;
  data?: string;
  valueWei?: string;
};

function normalizeData(
  value: string | undefined
): string {
  const data = value?.trim() || "0x";

  if (data.length > 131074) {
    throw new GuardedSignerRejectedError(
      "transaction data is too large",
      "TRANSACTION_DATA_TOO_LARGE"
    );
  }

  if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    throw new GuardedSignerRejectedError(
      "invalid transaction data",
      "INVALID_TRANSACTION"
    );
  }

  return data.toLowerCase();
}

function normalizeValue(
  value: string | undefined
): bigint {
  const raw = value ?? "0";

  if (raw.length > 78 || !/^\d+$/.test(raw)) {
    throw new GuardedSignerRejectedError(
      "valueWei must be an unsigned integer",
      "INVALID_TRANSACTION"
    );
  }

  return BigInt(raw);
}

export function normalizeRequestedExecution(
  input: GuardedExecutionInput
): Readonly<{
  to: string;
  data: string;
  value: bigint;
}> {
  return Object.freeze({
    to: getAddress(input.to),
    data: normalizeData(input.data),
    value: normalizeValue(input.valueWei)
  });
}

function assertNoUnsupportedEnvelopeFields(
  transaction: TransactionRequest
): void {
  const accessList = transaction.accessList;

  if (
    Array.isArray(accessList) &&
    accessList.length > 0
  ) {
    throw new GuardedSignerRejectedError(
      "access lists are not supported",
      "UNSUPPORTED_ACCESS_LIST"
    );
  }

  if (
    transaction.authorizationList &&
    transaction.authorizationList.length > 0
  ) {
    throw new GuardedSignerRejectedError(
      "EIP-7702 authorization lists are not supported",
      "UNSUPPORTED_AUTHORIZATION_LIST"
    );
  }

  if (
    transaction.blobs ||
    transaction.blobVersionedHashes
  ) {
    throw new GuardedSignerRejectedError(
      "blob transaction fields are not supported",
      "UNSUPPORTED_BLOB_TRANSACTION"
    );
  }
}

export function immutablePopulatedTransaction(
  populated: TransactionRequest,
  expected: {
    sender: string;
    chainId: bigint;
    nonce: number;
    to: string;
    data: string;
    value: bigint;
  }
): Readonly<TransactionRequest> {
  if (!populated.to || !isAddress(String(populated.to))) {
    throw new GuardedSignerRejectedError(
      "Signer.populateTransaction returned an invalid destination",
      "POPULATED_TRANSACTION_INVALID"
    );
  }

  const to = getAddress(String(populated.to));
  const data = normalizeData(
    populated.data === null || populated.data === undefined
      ? "0x"
      : String(populated.data)
  );
  const value = populated.value === null || populated.value === undefined
    ? 0n
    : BigInt(populated.value);
  const nonce = populated.nonce === null || populated.nonce === undefined
    ? null
    : Number(populated.nonce);
  const chainId = populated.chainId === null || populated.chainId === undefined
    ? null
    : BigInt(populated.chainId);

  if (
    populated.from &&
    getAddress(String(populated.from)) !== expected.sender
  ) {
    throw new GuardedSignerRejectedError(
      "populateTransaction changed the sender",
      "POPULATED_SENDER_MISMATCH"
    );
  }

  if (
    to !== expected.to ||
    data !== expected.data ||
    value !== expected.value ||
    nonce !== expected.nonce ||
    chainId !== expected.chainId
  ) {
    throw new GuardedSignerRejectedError(
      "populateTransaction changed the requested tx",
      "POPULATED_EXECUTION_MISMATCH"
    );
  }

  assertNoUnsupportedEnvelopeFields(populated);

  const canonical: TransactionRequest = {
    to,
    data,
    value,
    nonce: expected.nonce,
    chainId: expected.chainId,
    type: populated.type,
    gasLimit: populated.gasLimit,
    gasPrice: populated.gasPrice,
    maxFeePerGas: populated.maxFeePerGas,
    maxPriorityFeePerGas:
      populated.maxPriorityFeePerGas
  };

  return Object.freeze(canonical);
}
