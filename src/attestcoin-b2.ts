import {
  Interface,
  solidityPackedKeccak256
} from "ethers";

export type MerklePathEntry = {
  hash: string;
  isLeft: boolean;
};

export const AUTHORIZATION_SOURCE_ABI = [
  "function AUTHORIZATION_COMMITMENT_DOMAIN() view returns (bytes32)",
  "function AUTHORIZATION_ID_DOMAIN() view returns (bytes32)",
  "function publishAuthorization((uint256 executionChainId,address sender,uint256 executionNonce,uint64 validUntil,uint8 actionCode,address target,bytes32 targetCodeHash,address asset,address counterpartyA,address counterpartyB,uint256 amountOrFlag) authorization) returns (bytes32 authorizationId,bytes32 commitment)",
  "function computeCommitment((uint256 executionChainId,address sender,uint256 executionNonce,uint64 validUntil,uint8 actionCode,address target,bytes32 targetCodeHash,address asset,address counterpartyA,address counterpartyB,uint256 amountOrFlag) authorization) view returns (bytes32)",
  "function computeExecutionBinding((uint256 executionChainId,address sender,uint256 executionNonce,uint64 validUntil,uint8 actionCode,address target,bytes32 targetCodeHash,address asset,address counterpartyA,address counterpartyB,uint256 amountOrFlag) authorization) pure returns (bytes32 callDataHash,uint256 nativeValueWei)",
  "event AuthorizationPublished(bytes32 indexed authorizationId,bytes32 indexed commitment,address indexed sender,uint256 nonce,uint256 executionChainId,uint256 executionNonce,uint64 validUntil,uint8 actionCode,address target,bytes32 targetCodeHash,address asset,address counterpartyA,address counterpartyB,uint256 amountOrFlag,bytes32 callDataHash,uint256 nativeValueWei)"
] as const;

export const authorizationSourceInterface =
  new Interface(AUTHORIZATION_SOURCE_ABI);


export function calculateTransactionIndex(
  siblings: readonly Pick<MerklePathEntry, "isLeft">[]
): bigint {
  if (siblings.length > 64) {
    throw new Error(
      "Merkle path cannot exceed 64 entries for a uint64 transaction index"
    );
  }

  let index = 0n;

  for (
    let depth = 0;
    depth < siblings.length;
    depth += 1
  ) {
    if (siblings[depth].isLeft) {
      index |= 1n << BigInt(depth);
    }
  }

  return index;
}

export function assertProofMatchesSourceReceipt(
  input: {
    proofChainKey: bigint | number | string;
    expectedChainKey: bigint | number | string;
    proofHeaderNumber: bigint | number | string;
    receiptBlockNumber: bigint | number | string;
    siblings: readonly Pick<MerklePathEntry, "isLeft">[];
    receiptTransactionIndex: bigint | number | string;
  }
): bigint {
  const proofChainKey =
    BigInt(input.proofChainKey);
  const expectedChainKey =
    BigInt(input.expectedChainKey);

  if (proofChainKey !== expectedChainKey) {
    throw new Error(
      `Proof chainKey ${proofChainKey} does not match configured source chainKey ${expectedChainKey}`
    );
  }

  const proofHeaderNumber =
    BigInt(input.proofHeaderNumber);
  const receiptBlockNumber =
    BigInt(input.receiptBlockNumber);

  if (proofHeaderNumber !== receiptBlockNumber) {
    throw new Error(
      `Proof block ${proofHeaderNumber} does not match source receipt block ${receiptBlockNumber}`
    );
  }

  const proofTransactionIndex =
    calculateTransactionIndex(
      input.siblings
    );

  const receiptTransactionIndex =
    BigInt(input.receiptTransactionIndex);

  if (
    proofTransactionIndex !==
    receiptTransactionIndex
  ) {
    throw new Error(
      `transaction index ${proofTransactionIndex} != receipt index ${receiptTransactionIndex}`
    );
  }

  return proofTransactionIndex;
}

export function computeProofTransactionKey(
  sourceChainKey: bigint | number | string,
  sourceBlockNumber: bigint | number | string,
  transactionIndex: bigint | number | string
): string {
  return solidityPackedKeccak256(
    ["uint64", "uint64", "uint64"],
    [
      BigInt(sourceChainKey),
      BigInt(sourceBlockNumber),
      BigInt(transactionIndex)
    ]
  );
}
