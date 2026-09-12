import {
  getAddress,
  isHexString,
  verifyTypedData
} from "ethers";

export const CONTROLLER_APPROVAL_DOMAIN_NAME =
  "AgentFirewall Controller Approval";
export const CONTROLLER_APPROVAL_DOMAIN_VERSION =
  "1";

export const CONTROLLER_APPROVAL_TYPES = {
  ControllerApproval: [
    { name: "authorizationId", type: "bytes32" },
    { name: "commitment", type: "bytes32" },
    { name: "executor", type: "address" },
    { name: "executionChainId", type: "uint256" },
    { name: "executionNonce", type: "uint256" },
    { name: "validUntil", type: "uint64" },
    { name: "registryAddress", type: "address" },
    { name: "sourceChainKey", type: "uint64" }
  ]
};

export const CONTROLLER_APPROVAL_V2_DOMAIN_VERSION =
  "2";

export const CONTROLLER_APPROVAL_V2_TYPES = {
  ControllerApproval: [
    ...CONTROLLER_APPROVAL_TYPES.ControllerApproval,
    { name: "maxGasLimit", type: "uint256" },
    { name: "maxFeePerGasWei", type: "uint256" },
    { name: "maxPriorityFeePerGasWei", type: "uint256" },
    { name: "maxTotalFeeWei", type: "uint256" }
  ]
};

export type ControllerFeeBinding = {
  maxGasLimit: string;
  maxFeePerGasWei: string;
  maxPriorityFeePerGasWei: string;
  maxTotalFeeWei: string;
};

export type ControllerApprovalMessage = {
  authorizationId: string;
  commitment: string;
  executor: string;
  executionChainId: string;
  executionNonce: string;
  validUntil: string;
  registryAddress: string;
  sourceChainKey: string;
};

function uintString(
  value: string,
  field: string,
  maxBits?: number
): string {
  if (!/^\d+$/.test(value)) {
    throw new Error(
      `${field} must be an unsigned integer`
    );
  }

  const parsed = BigInt(value);

  if (
    maxBits !== undefined &&
    parsed > (1n << BigInt(maxBits)) - 1n
  ) {
    throw new Error(
      `${field} exceeds uint${maxBits}`
    );
  }

  return parsed.toString();
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

  return value.toLowerCase();
}

export function normalizeControllerApprovalMessage(
  input: ControllerApprovalMessage
): ControllerApprovalMessage {
  return {
    authorizationId:
      bytes32(input.authorizationId, "authorizationId"),
    commitment:
      bytes32(input.commitment, "commitment"),
    executor:
      getAddress(input.executor),
    executionChainId:
      uintString(input.executionChainId, "executionChainId"),
    executionNonce:
      uintString(input.executionNonce, "executionNonce"),
    validUntil:
      uintString(input.validUntil, "validUntil", 64),
    registryAddress:
      getAddress(input.registryAddress),
    sourceChainKey:
      uintString(input.sourceChainKey, "sourceChainKey", 64)
  };
}

export function controllerApprovalTypedData(
  input: ControllerApprovalMessage
) {
  const message =
    normalizeControllerApprovalMessage(input);

  return {
    domain: {
      name: CONTROLLER_APPROVAL_DOMAIN_NAME,
      version: CONTROLLER_APPROVAL_DOMAIN_VERSION,
      chainId: BigInt(message.executionChainId)
    },
    types: CONTROLLER_APPROVAL_TYPES,
    message: {
      authorizationId: message.authorizationId,
      commitment: message.commitment,
      executor: message.executor,
      executionChainId: BigInt(message.executionChainId),
      executionNonce: BigInt(message.executionNonce),
      validUntil: BigInt(message.validUntil),
      registryAddress: message.registryAddress,
      sourceChainKey: BigInt(message.sourceChainKey)
    }
  } as const;
}

export function controllerApprovalTypedDataV2(
  input: ControllerApprovalMessage,
  fee: ControllerFeeBinding
) {
  const message =
    normalizeControllerApprovalMessage(input);
  const normalizedFee = {
    maxGasLimit: uintString(fee.maxGasLimit, "maxGasLimit"),
    maxFeePerGasWei: uintString(fee.maxFeePerGasWei, "maxFeePerGasWei"),
    maxPriorityFeePerGasWei: uintString(
      fee.maxPriorityFeePerGasWei,
      "maxPriorityFeePerGasWei"
    ),
    maxTotalFeeWei: uintString(fee.maxTotalFeeWei, "maxTotalFeeWei")
  };

  return {
    domain: {
      name: CONTROLLER_APPROVAL_DOMAIN_NAME,
      version: CONTROLLER_APPROVAL_V2_DOMAIN_VERSION,
      chainId: BigInt(message.executionChainId)
    },
    types: CONTROLLER_APPROVAL_V2_TYPES,
    message: {
      authorizationId: message.authorizationId,
      commitment: message.commitment,
      executor: message.executor,
      executionChainId: BigInt(message.executionChainId),
      executionNonce: BigInt(message.executionNonce),
      validUntil: BigInt(message.validUntil),
      registryAddress: message.registryAddress,
      sourceChainKey: BigInt(message.sourceChainKey),
      maxGasLimit: BigInt(normalizedFee.maxGasLimit),
      maxFeePerGasWei: BigInt(normalizedFee.maxFeePerGasWei),
      maxPriorityFeePerGasWei: BigInt(normalizedFee.maxPriorityFeePerGasWei),
      maxTotalFeeWei: BigInt(normalizedFee.maxTotalFeeWei)
    }
  } as const;
}

export function verifyControllerApprovalV2(
  trustedController: string,
  input: ControllerApprovalMessage,
  fee: ControllerFeeBinding,
  signature: string
): string {
  const expected = getAddress(trustedController);

  if (
    !isHexString(signature) ||
    (signature.length !== 130 && signature.length !== 132)
  ) {
    throw new Error(
      "Controller approval must be a 64-byte compact or 65-byte ECDSA signature"
    );
  }

  const typed = controllerApprovalTypedDataV2(input, fee);
  const recovered = getAddress(
    verifyTypedData(
      typed.domain,
      typed.types,
      typed.message,
      signature
    )
  );

  if (recovered !== expected) {
    throw new Error(
      `Controller approval signer ${recovered} does not match trusted controller ${expected}`
    );
  }

  return recovered;
}

export function verifyControllerApproval(
  trustedController: string,
  input: ControllerApprovalMessage,
  signature: string
): string {
  const expected =
    getAddress(trustedController);

  if (
    !isHexString(signature) ||
    (signature.length !== 130 && signature.length !== 132)
  ) {
    throw new Error(
      "Controller approval must be a 64-byte compact or 65-byte ECDSA signature"
    );
  }

  const typed =
    controllerApprovalTypedData(input);

  const recovered = getAddress(
    verifyTypedData(
      typed.domain,
      typed.types,
      typed.message,
      signature
    )
  );

  if (recovered !== expected) {
    throw new Error(
      `Controller approval signer ${recovered} does not match trusted controller ${expected}`
    );
  }

  return recovered;
}
