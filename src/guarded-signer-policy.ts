import type {
  Provider,
  TransactionRequest
} from "ethers";

import type {
  SecurityPolicy
} from "./analyzer.js";

import {
  GuardedSignerRejectedError
} from "./guarded-signer-error.js";

export type FeeSafetyPolicy = {
  maxGasLimit: string;
  maxFeePerGasWei: string;
  maxPriorityFeePerGasWei: string;
  maxTotalFeeWei: string;
};

export type GuardedSignerOptions = {
  trustedController: string;
  feePolicy: FeeSafetyPolicy;
  rpcSourceLabel?: string;
  secondaryExecutionProvider?: Provider;
};

function requireUnsigned(
  value: string,
  field: string
): bigint {
  if (value.length > 78 || !/^\d+$/.test(value)) {
    throw new GuardedSignerRejectedError(
      `${field} must be an unsigned integer`,
      "INVALID_FEE_POLICY"
    );
  }

  return BigInt(value);
}

export function normalizeFeeSafetyPolicy(
  policy: FeeSafetyPolicy
): Readonly<FeeSafetyPolicy> {
  const maxGasLimit = requireUnsigned(
    policy.maxGasLimit,
    "maxGasLimit"
  );
  const maxFeePerGasWei = requireUnsigned(
    policy.maxFeePerGasWei,
    "maxFeePerGasWei"
  );
  const maxPriorityFeePerGasWei = requireUnsigned(
    policy.maxPriorityFeePerGasWei,
    "maxPriorityFeePerGasWei"
  );
  const maxTotalFeeWei = requireUnsigned(
    policy.maxTotalFeeWei,
    "maxTotalFeeWei"
  );

  if (maxGasLimit === 0n) {
    throw new GuardedSignerRejectedError(
      "maxGasLimit must be greater than zero",
      "INVALID_FEE_POLICY"
    );
  }

  if (maxFeePerGasWei === 0n) {
    throw new GuardedSignerRejectedError(
      "maxFeePerGasWei must be greater than zero",
      "INVALID_FEE_POLICY"
    );
  }

  if (maxTotalFeeWei === 0n) {
    throw new GuardedSignerRejectedError(
      "maxTotalFeeWei must be greater than zero",
      "INVALID_FEE_POLICY"
    );
  }

  if (maxPriorityFeePerGasWei > maxFeePerGasWei) {
    throw new GuardedSignerRejectedError(
      "maxPriorityFeePerGasWei cannot exceed maxFeePerGasWei",
      "INVALID_FEE_POLICY"
    );
  }

  return Object.freeze({
    maxGasLimit: maxGasLimit.toString(),
    maxFeePerGasWei: maxFeePerGasWei.toString(),
    maxPriorityFeePerGasWei: maxPriorityFeePerGasWei.toString(),
    maxTotalFeeWei: maxTotalFeeWei.toString()
  });
}

export function snapshotSecurityPolicy(
  policy: SecurityPolicy
): Readonly<SecurityPolicy> {
  if (
    policy.maxNativeValueWei !== undefined &&
    (policy.maxNativeValueWei.length > 78 ||
      !/^\d+$/.test(policy.maxNativeValueWei))
  ) {
    throw new GuardedSignerRejectedError(
      "invalid maxNativeValueWei",
      "INVALID_SECURITY_POLICY"
    );
  }

  return Object.freeze({
    ...(policy.maxNativeValueWei !== undefined
      ? { maxNativeValueWei: policy.maxNativeValueWei }
      : {}),
    ...(policy.allowedTargets !== undefined
      ? { allowedTargets: Object.freeze([...policy.allowedTargets]) as unknown as string[] }
      : {}),
    ...(policy.blockedTargets !== undefined
      ? { blockedTargets: Object.freeze([...policy.blockedTargets]) as unknown as string[] }
      : {}),
    ...(policy.requireKnownCalldata !== undefined
      ? { requireKnownCalldata: policy.requireKnownCalldata }
      : {})
  });
}

export function enforceFeeSafety(
  transaction: TransactionRequest,
  policy: FeeSafetyPolicy
): {
  gasLimit: bigint;
  maxUnitFeeWei: bigint;
  worstCaseTotalFeeWei: bigint;
} {
  const maxGasLimit = requireUnsigned(
    policy.maxGasLimit,
    "maxGasLimit"
  );
  const maxFeePerGas = requireUnsigned(
    policy.maxFeePerGasWei,
    "maxFeePerGasWei"
  );
  const maxPriorityFeePerGas = requireUnsigned(
    policy.maxPriorityFeePerGasWei,
    "maxPriorityFeePerGasWei"
  );
  const maxTotalFee = requireUnsigned(
    policy.maxTotalFeeWei,
    "maxTotalFeeWei"
  );

  const gasLimit = transaction.gasLimit === null ||
    transaction.gasLimit === undefined
      ? null
      : BigInt(transaction.gasLimit);

  if (!gasLimit || gasLimit <= 0n) {
    throw new GuardedSignerRejectedError(
      "Populated transaction has no positive gasLimit",
      "FEE_GAS_LIMIT_MISSING"
    );
  }

  if (gasLimit > maxGasLimit) {
    throw new GuardedSignerRejectedError(
      `gasLimit ${gasLimit} exceeds policy ceiling ${maxGasLimit}`,
      "FEE_GAS_LIMIT_EXCEEDED"
    );
  }

  const type = transaction.type === null ||
    transaction.type === undefined
      ? null
      : Number(transaction.type);

  let maxUnitFeeWei: bigint;

  if (type === 2) {
    if (
      transaction.maxFeePerGas === null ||
      transaction.maxFeePerGas === undefined ||
      transaction.maxPriorityFeePerGas === null ||
      transaction.maxPriorityFeePerGas === undefined
    ) {
      throw new GuardedSignerRejectedError(
        "missing EIP-1559 fee fields",
        "FEE_FIELDS_MISSING"
      );
    }

    const actualMaxFee = BigInt(transaction.maxFeePerGas);
    const actualPriority = BigInt(transaction.maxPriorityFeePerGas);

    if (actualMaxFee < 0n || actualPriority < 0n) {
      throw new GuardedSignerRejectedError(
        "EIP-1559 fee fields must be non-negative",
        "INVALID_FEE_VALUE"
      );
    }

    if (actualMaxFee > maxFeePerGas) {
      throw new GuardedSignerRejectedError(
        `maxFeePerGas ${actualMaxFee} exceeds policy ceiling ${maxFeePerGas}`,
        "MAX_FEE_PER_GAS_EXCEEDED"
      );
    }

    if (actualPriority > maxPriorityFeePerGas) {
      throw new GuardedSignerRejectedError(
        `maxPriorityFeePerGas ${actualPriority} exceeds policy ceiling ${maxPriorityFeePerGas}`,
        "MAX_PRIORITY_FEE_PER_GAS_EXCEEDED"
      );
    }

    if (actualPriority > actualMaxFee) {
      throw new GuardedSignerRejectedError(
        "maxPriorityFeePerGas exceeds maxFeePerGas",
        "INVALID_FEE_RELATION"
      );
    }

    maxUnitFeeWei = actualMaxFee;
  } else if (type === 0) {
    if (
      transaction.gasPrice === null ||
      transaction.gasPrice === undefined
    ) {
      throw new GuardedSignerRejectedError(
        "Legacy transaction is missing gasPrice",
        "FEE_FIELDS_MISSING"
      );
    }

    const gasPrice = BigInt(transaction.gasPrice);

    if (gasPrice < 0n) {
      throw new GuardedSignerRejectedError(
        "Legacy gasPrice must be non-negative",
        "INVALID_FEE_VALUE"
      );
    }

    if (gasPrice > maxFeePerGas) {
      throw new GuardedSignerRejectedError(
        `gasPrice ${gasPrice} exceeds policy maxFeePerGasWei ceiling ${maxFeePerGas}`,
        "MAX_FEE_PER_GAS_EXCEEDED"
      );
    }

    maxUnitFeeWei = gasPrice;
  } else {
    throw new GuardedSignerRejectedError(
      `unsupported transaction type: ${String(type)}`,
      "UNSUPPORTED_TRANSACTION_TYPE"
    );
  }

  const worstCaseTotalFeeWei = gasLimit * maxUnitFeeWei;

  if (worstCaseTotalFeeWei > maxTotalFee) {
    throw new GuardedSignerRejectedError(
      `Worst-case fee ${worstCaseTotalFeeWei} wei exceeds total fee budget ${maxTotalFee} wei`,
      "TOTAL_FEE_BUDGET_EXCEEDED"
    );
  }

  return {
    gasLimit,
    maxUnitFeeWei,
    worstCaseTotalFeeWei
  };
}
