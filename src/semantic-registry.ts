import {
  AbiCoder,
  Interface,
  ZeroAddress,
  getAddress,
  id,
  isHexString,
  keccak256
} from "ethers";

import {
  AUTHORIZATION_SOURCE_ABI,
  authorizationSourceInterface
} from "./attestcoin-b2.js";

export const AUTHORIZATION_ID_DOMAIN =
  id("AgentFirewall.AuthorizationId.v1");

export const AUTHORIZATION_COMMITMENT_DOMAIN =
  id("AgentFirewall.Authorization.v3");

export const VERIFIED_AUTHORIZATION_REGISTRY_ABI = [
  "constructor(uint64 sourceChainKey,uint256 sourceChainId,address authorizationSource)",
  "error WrongSourceChain(uint64 expected,uint64 actual)",
  "error TransactionAlreadyProcessed(bytes32 transactionKey)",
  "error AuthorizationAlreadyRecorded(bytes32 authorizationId)",
  "error MerklePathTooDeep(uint256 length)",
  "error VerificationFailed()",
  "error SourceTransactionFailed(uint256 receiptStatus)",
  "error TrustedAuthorizationEventCount(uint256 count)",
  "error InvalidAuthorizationEventTopics(uint256 count)",
  "error AuthorizationExpired(uint64 validUntil,uint256 currentTime)",
  "error InvalidAuthorizationShape()",
  "error UnsupportedAction(uint8 actionCode)",
  "error EventCommitmentMismatch(bytes32 emitted,bytes32 recomputed)",
  "error EventExecutionBindingMismatch()",
  "error AuthorizationIdMismatch(bytes32 emitted,bytes32 recomputed)",
  "function trustedSourceChainKey() view returns (uint64)",
  "function trustedSourceChainId() view returns (uint256)",
  "function trustedAuthorizationSource() view returns (address)",
  "function AUTHORIZATION_COMMITMENT_DOMAIN() view returns (bytes32)",
  "function AUTHORIZATION_ID_DOMAIN() view returns (bytes32)",
  "function submitVerifiedAuthorization(uint64 chainKey,uint64 blockHeight,bytes encodedTransaction,bytes32 merkleRoot,(bytes32 hash,bool isLeft)[] siblings,bytes32 lowerEndpointDigest,bytes32[] continuityRoots) returns (bytes32 authorizationId)",
  "function getAuthorization(bytes32 authorizationId) view returns (bytes32 commitment,uint64 sourceChainKey,uint64 sourceBlockNumber,uint64 transactionIndex,uint64 validUntil,bool verified)",
  "function getAuthorizationEvidence(bytes32 authorizationId) view returns (bytes32 commitment,uint64 sourceChainKey,uint64 sourceBlockNumber,uint64 transactionIndex,uint64 validUntil,address sourceSender,bytes32 transactionKey,bytes32 provenTransactionHash,bool verified)",
  "function processedTransactions(bytes32 transactionKey) view returns (bool)",
  "function computeTransactionKey(uint64 chainKey,uint64 blockHeight,uint64 transactionIndex) pure returns (bytes32)",
  "event VerifiedAuthorizationRecorded(bytes32 indexed authorizationId,bytes32 indexed commitment,address indexed sourceSender,uint64 sourceChainKey,uint64 sourceBlockNumber,uint64 transactionIndex,uint64 validUntil,bytes32 transactionKey,bytes32 provenTransactionHash)"
] as const;

export const verifiedAuthorizationRegistryInterface =
  new Interface(
    VERIFIED_AUTHORIZATION_REGISTRY_ABI
  );

export const AUTHORIZATION_PUBLISHED_EVENT =
  authorizationSourceInterface.getEvent(
    "AuthorizationPublished"
  );

if (!AUTHORIZATION_PUBLISHED_EVENT) {
  throw new Error(
    "AuthorizationPublished event is missing from AUTHORIZATION_SOURCE_ABI"
  );
}

export const AUTHORIZATION_PUBLISHED_TOPIC =
  AUTHORIZATION_PUBLISHED_EVENT.topicHash;

export type SourceReceiptLog = {
  address: string;
  topics: readonly string[];
  data: string;
  index?: number;
};

export type SourceAuthorizationEvidence = {
  authorizationId: string;
  commitment: string;
  sender: string;
  nonce: string;
  executionChainId: string;
  executionNonce: string;
  validUntil: string;
  actionCode: number;
  target: string;
  targetCodeHash: string;
  asset: string;
  counterpartyA: string;
  counterpartyB: string;
  amountOrFlag: string;
  callDataHash: string;
  nativeValueWei: string;
  logIndex: number | null;
};

function bytes32(
  value: unknown,
  field: string
): string {
  if (
    typeof value !== "string" ||
    !isHexString(value, 32)
  ) {
    throw new Error(
      `${field} must be exactly 32 bytes`
    );
  }

  return value.toLowerCase();
}

function uint(
  value: unknown,
  field: string
): string {
  try {
    const parsed = BigInt(
      value as bigint | number | string
    );

    if (parsed < 0n) {
      throw new Error("negative");
    }

    return parsed.toString();
  } catch {
    throw new Error(
      `${field} must be an unsigned integer`
    );
  }
}

export function parseTrustedAuthorizationEvidence(
  logs: readonly SourceReceiptLog[],
  trustedSourceAddress: string
): SourceAuthorizationEvidence {
  const trusted =
    getAddress(trustedSourceAddress);

  const candidates =
    logs.filter(log => {
      if (
        getAddress(log.address) !== trusted ||
        log.topics.length === 0 ||
        log.topics[0].toLowerCase() !==
          AUTHORIZATION_PUBLISHED_TOPIC.toLowerCase()
      ) {
        return false;
      }

      return true;
    });

  if (candidates.length !== 1) {
    throw new Error(
      `Expected exactly one AuthorizationPublished log from ${trusted}, found ${candidates.length}`
    );
  }

  const log = candidates[0];
  const parsed =
    authorizationSourceInterface.parseLog({
      topics: [...log.topics],
      data: log.data
    });

  if (
    !parsed ||
    parsed.name !== "AuthorizationPublished"
  ) {
    throw new Error(
      "Unable to decode trusted AuthorizationPublished log"
    );
  }

  const args = parsed.args;

  return {
    authorizationId:
      bytes32(
        args.authorizationId,
        "authorizationId"
      ),
    commitment:
      bytes32(
        args.commitment,
        "commitment"
      ),
    sender:
      getAddress(args.sender),
    nonce:
      uint(args.nonce, "nonce"),
    executionChainId:
      uint(
        args.executionChainId,
        "executionChainId"
      ),
    executionNonce:
      uint(
        args.executionNonce,
        "executionNonce"
      ),
    validUntil:
      uint(args.validUntil, "validUntil"),
    actionCode:
      Number(
        BigInt(args.actionCode)
      ),
    target:
      getAddress(args.target),
    targetCodeHash:
      bytes32(
        args.targetCodeHash,
        "targetCodeHash"
      ),
    asset:
      getAddress(args.asset),
    counterpartyA:
      getAddress(args.counterpartyA),
    counterpartyB:
      getAddress(args.counterpartyB),
    amountOrFlag:
      uint(
        args.amountOrFlag,
        "amountOrFlag"
      ),
    callDataHash:
      bytes32(
        args.callDataHash,
        "callDataHash"
      ),
    nativeValueWei:
      uint(
        args.nativeValueWei,
        "nativeValueWei"
      ),
    logIndex:
      typeof log.index === "number"
        ? log.index
        : null
  };
}


const executionInterface =
  new Interface([
    "function approve(address spender,uint256 amount)",
    "function transfer(address to,uint256 amount)",
    "function transferFrom(address from,address to,uint256 amount)",
    "function setApprovalForAll(address operator,bool approved)"
  ]);

const coder =
  AbiCoder.defaultAbiCoder();

function normalizedAddress(
  value: string,
  field: string
): string {
  try {
    return getAddress(value);
  } catch {
    throw new Error(
      `${field} must be a valid address`
    );
  }
}

function evidenceShape(
  evidence: SourceAuthorizationEvidence
): void {
  const target =
    normalizedAddress(
      evidence.target,
      "target"
    );
  const asset =
    normalizedAddress(
      evidence.asset,
      "asset"
    );
  const counterpartyA =
    normalizedAddress(
      evidence.counterpartyA,
      "counterpartyA"
    );
  const counterpartyB =
    normalizedAddress(
      evidence.counterpartyB,
      "counterpartyB"
    );

  if (
    target === ZeroAddress ||
    evidence.targetCodeHash ===
      `0x${"00".repeat(32)}` ||
    BigInt(evidence.validUntil) === 0n
  ) {
    throw new Error(
      "Authorization evidence has an invalid target, targetCodeHash, or validUntil"
    );
  }

  switch (evidence.actionCode) {
    case 1:
      if (
        asset !== ZeroAddress ||
        counterpartyA !== target ||
        counterpartyB !== ZeroAddress
      ) {
        throw new Error(
          "Native-transfer authorization evidence has an invalid shape"
        );
      }
      return;

    case 2:
    case 3:
      if (
        asset !== target ||
        counterpartyA === ZeroAddress ||
        counterpartyB !== ZeroAddress
      ) {
        throw new Error(
          "ERC-20 authorization evidence has an invalid shape"
        );
      }
      return;

    case 4:
      if (
        asset !== target ||
        counterpartyA === ZeroAddress ||
        counterpartyB === ZeroAddress
      ) {
        throw new Error(
          "ERC-20 transferFrom authorization evidence has an invalid shape"
        );
      }
      return;

    case 5:
      if (
        asset !== target ||
        counterpartyA === ZeroAddress ||
        counterpartyB !== ZeroAddress ||
        BigInt(evidence.amountOrFlag) > 1n
      ) {
        throw new Error(
          "NFT operator authorization evidence has an invalid shape"
        );
      }
      return;

    default:
      throw new Error(
        `Unsupported authorization actionCode ${evidence.actionCode}`
      );
  }
}

export function expectedEvidenceExecutionBinding(
  evidence: SourceAuthorizationEvidence
): {
  callDataHash: string;
  nativeValueWei: string;
} {
  switch (evidence.actionCode) {
    case 1:
      return {
        callDataHash:
          keccak256("0x"),
        nativeValueWei:
          BigInt(evidence.amountOrFlag).toString()
      };

    case 2:
      return {
        callDataHash:
          keccak256(
            executionInterface.encodeFunctionData(
              "approve",
              [
                evidence.counterpartyA,
                BigInt(evidence.amountOrFlag)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case 3:
      return {
        callDataHash:
          keccak256(
            executionInterface.encodeFunctionData(
              "transfer",
              [
                evidence.counterpartyA,
                BigInt(evidence.amountOrFlag)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case 4:
      return {
        callDataHash:
          keccak256(
            executionInterface.encodeFunctionData(
              "transferFrom",
              [
                evidence.counterpartyA,
                evidence.counterpartyB,
                BigInt(evidence.amountOrFlag)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case 5:
      return {
        callDataHash:
          keccak256(
            executionInterface.encodeFunctionData(
              "setApprovalForAll",
              [
                evidence.counterpartyA,
                BigInt(evidence.amountOrFlag) === 1n
              ]
            )
          ),
        nativeValueWei: "0"
      };

    default:
      throw new Error(
        `Unsupported authorization actionCode ${evidence.actionCode}`
      );
  }
}

export function recomputeEvidenceCommitment(
  evidence: SourceAuthorizationEvidence
): string {
  return keccak256(
    coder.encode(
      [
        "bytes32",
        "uint256",
        "address",
        "uint256",
        "uint64",
        "uint8",
        "address",
        "bytes32",
        "address",
        "address",
        "address",
        "uint256",
        "bytes32",
        "uint256"
      ],
      [
        AUTHORIZATION_COMMITMENT_DOMAIN,
        evidence.executionChainId,
        evidence.sender,
        evidence.executionNonce,
        evidence.validUntil,
        evidence.actionCode,
        evidence.target,
        evidence.targetCodeHash,
        evidence.asset,
        evidence.counterpartyA,
        evidence.counterpartyB,
        evidence.amountOrFlag,
        evidence.callDataHash,
        evidence.nativeValueWei
      ]
    )
  );
}

export function recomputeAuthorizationId(
  evidence: SourceAuthorizationEvidence,
  sourceChainId: bigint | number | string,
  sourceContract: string
): string {
  return keccak256(
    coder.encode(
      [
        "bytes32",
        "uint256",
        "address",
        "address",
        "uint256",
        "uint64",
        "bytes32"
      ],
      [
        AUTHORIZATION_ID_DOMAIN,
        BigInt(sourceChainId),
        getAddress(sourceContract),
        evidence.sender,
        evidence.nonce,
        evidence.validUntil,
        evidence.commitment
      ]
    )
  );
}

export function validateSourceAuthorizationEvidence(
  evidence: SourceAuthorizationEvidence,
  sourceChainId: bigint | number | string,
  sourceContract: string
): void {
  evidenceShape(evidence);

  const expectedBinding =
    expectedEvidenceExecutionBinding(
      evidence
    );

  if (
    expectedBinding.callDataHash.toLowerCase() !==
      evidence.callDataHash.toLowerCase() ||
    expectedBinding.nativeValueWei !==
      BigInt(evidence.nativeValueWei).toString()
  ) {
    throw new Error(
      "AuthorizationPublished execution binding does not match its semantic fields"
    );
  }

  const commitment =
    recomputeEvidenceCommitment(
      evidence
    ).toLowerCase();

  if (
    commitment !==
    evidence.commitment.toLowerCase()
  ) {
    throw new Error(
      `authorization commitment mismatch: ${evidence.commitment}`
    );
  }

  const authorizationId =
    recomputeAuthorizationId(
      evidence,
      sourceChainId,
      sourceContract
    ).toLowerCase();

  if (
    authorizationId !==
    evidence.authorizationId.toLowerCase()
  ) {
    throw new Error(
      `authorization id mismatch: ${evidence.authorizationId}`
    );
  }
}

export type SemanticRegistryTrustAnchors = {
  trustedSourceChainKey: bigint | number | string;
  trustedSourceChainId: bigint | number | string;
  trustedAuthorizationSource: string;
  authorizationCommitmentDomain: string;
  authorizationIdDomain: string;
};

export function validateSemanticRegistryTrustAnchors(
  actual: SemanticRegistryTrustAnchors,
  expected: {
    sourceChainKey: bigint | number | string;
    sourceChainId: bigint | number | string;
    authorizationSource: string;
  }
): void {
  if (
    BigInt(actual.trustedSourceChainKey) !==
    BigInt(expected.sourceChainKey)
  ) {
    throw new Error(
      `Registry trusts chainKey ${actual.trustedSourceChainKey}, expected ${expected.sourceChainKey}`
    );
  }

  if (
    BigInt(actual.trustedSourceChainId) !==
    BigInt(expected.sourceChainId)
  ) {
    throw new Error(
      `registry chain id mismatch: ${actual.trustedSourceChainId}`
    );
  }

  if (
    getAddress(actual.trustedAuthorizationSource) !==
    getAddress(expected.authorizationSource)
  ) {
    throw new Error(
      `registry source mismatch: ${actual.trustedAuthorizationSource}`
    );
  }

  if (
    actual.authorizationCommitmentDomain.toLowerCase() !==
    AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase()
  ) {
    throw new Error(
      `Registry commitment domain mismatch: ${actual.authorizationCommitmentDomain}`
    );
  }

  if (
    actual.authorizationIdDomain.toLowerCase() !==
    AUTHORIZATION_ID_DOMAIN.toLowerCase()
  ) {
    throw new Error(
      `Registry authorization-id domain mismatch: ${actual.authorizationIdDomain}`
    );
  }
}

export type SolidityLinkReference = {
  start: number;
  length: number;
};

export type SolidityLinkReferences = Record<
  string,
  Record<string, readonly SolidityLinkReference[]>
>;

export type SolidityByteRanges = Record<
  string,
  readonly SolidityLinkReference[]
>;

export function linkSolidityBytecode(
  unlinkedBytecode: string,
  linkReferences: SolidityLinkReferences,
  libraries: Record<string, string>
): string {
  let linked = unlinkedBytecode.startsWith("0x")
    ? unlinkedBytecode.slice(2)
    : unlinkedBytecode;

  for (const [source, sourceLibraries] of Object.entries(linkReferences)) {
    for (const [libraryName, references] of Object.entries(sourceLibraries)) {
      const address =
        libraries[`${source}:${libraryName}`] ??
        libraries[libraryName];

      if (!address) {
        throw new Error(
          `Missing deployment address for Solidity library ${source}:${libraryName}`
        );
      }

      const replacement =
        getAddress(address)
          .slice(2)
          .toLowerCase();

      for (const reference of references) {
        if (reference.length !== 20) {
          throw new Error(
            `Unexpected link width ${reference.length} for ${source}:${libraryName}`
          );
        }

        const start = reference.start * 2;
        const length = reference.length * 2;

        if (
          start < 0 ||
          start + length > linked.length
        ) {
          throw new Error(
            `Link reference for ${source}:${libraryName} is outside deployment bytecode`
          );
        }

        linked =
          linked.slice(0, start) +
          replacement +
          linked.slice(start + length);
      }
    }
  }

  if (!/^[0-9a-fA-F]+$/.test(linked)) {
    throw new Error(
      "Linked deployment bytecode still contains unresolved placeholders"
    );
  }

  return `0x${linked}`;
}

export function maskSolidityByteRanges(
  bytecode: string,
  ranges: SolidityByteRanges
): string {
  let masked =
    bytecode.startsWith("0x")
      ? bytecode.slice(2)
      : bytecode;

  if (!/^[0-9a-fA-F]+$/.test(masked)) {
    throw new Error(
      "Bytecode must be fully linked hexadecimal before masking compiler ranges"
    );
  }

  for (const references of Object.values(ranges)) {
    for (const reference of references) {
      const start = reference.start * 2;
      const length = reference.length * 2;

      if (
        reference.start < 0 ||
        reference.length <= 0 ||
        start + length > masked.length
      ) {
        throw new Error(
          "Compiler byte range is outside runtime bytecode"
        );
      }

      masked =
        masked.slice(0, start) +
        "0".repeat(length) +
        masked.slice(start + length);
    }
  }

  return `0x${masked.toLowerCase()}`;
}

export const AUTHORIZATION_SOURCE_EVENT_ABI =
  AUTHORIZATION_SOURCE_ABI;
