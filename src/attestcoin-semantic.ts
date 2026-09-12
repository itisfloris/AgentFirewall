import {
  Contract,
  JsonRpcProvider,
  Wallet,
  getAddress,
  isHexString,
  keccak256
} from "ethers";

import {
  existsSync,
  readFileSync,
  writeFileSync
} from "node:fs";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  fetchAttestcoinProof,
  verifyAttestcoinProof
} from "./attestcoin-native.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  AUTHORIZATION_SOURCE_ABI,
  assertProofMatchesSourceReceipt,
  computeProofTransactionKey
} from "./attestcoin-b2.js";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN,
  AUTHORIZATION_ID_DOMAIN,
  VERIFIED_AUTHORIZATION_REGISTRY_ABI,
  parseTrustedAuthorizationEvidence,
  validateSemanticRegistryTrustAnchors,
  validateSourceAuthorizationEvidence,
  verifiedAuthorizationRegistryInterface
} from "./semantic-registry.js";

import {
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

function requiredEnv(
  name: string
): string {
  const value =
    process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}`
    );
  }

  return value;
}

function positiveIntegerValue(
  name: string,
  raw: string
): number {
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `${name} must be an unsigned integer`
    );
  }

  const value = Number(raw);

  if (!Number.isSafeInteger(value)) {
    throw new Error(
      `${name} is outside the safe integer range`
    );
  }

  return value;
}

function errorText(
  error: unknown
): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }

  return String(error);
}

const DETERMINISTIC_REGISTRY_ERRORS = new Set([
  "WrongSourceChain",
  "TransactionAlreadyProcessed",
  "AuthorizationAlreadyRecorded",
  "MerklePathTooDeep",
  "VerificationFailed",
  "SourceTransactionFailed",
  "TrustedAuthorizationEventCount",
  "InvalidAuthorizationEventTopics",
  "AuthorizationExpired",
  "InvalidAuthorizationShape",
  "UnsupportedAction",
  "EventCommitmentMismatch",
  "EventExecutionBindingMismatch",
  "AuthorizationIdMismatch"
]);

function findRevertData(
  value: unknown,
  depth = 0
): string | null {
  if (depth > 4) {
    return null;
  }

  if (
    typeof value === "string" &&
    isHexString(value) &&
    value.length >= 10
  ) {
    return value;
  }

  if (
    !value ||
    typeof value !== "object"
  ) {
    return null;
  }

  const record =
    value as Record<string, unknown>;

  for (const key of [
    "data",
    "error",
    "info",
    "cause"
  ]) {
    const found = findRevertData(
      record[key],
      depth + 1
    );

    if (found) {
      return found;
    }
  }

  return null;
}

function deterministicSemanticFailure(
  error: unknown
): boolean {
  const revertData =
    findRevertData(error);

  if (revertData) {
    try {
      const decoded =
        verifiedAuthorizationRegistryInterface.parseError(
          revertData
        );

      if (
        decoded &&
        DETERMINISTIC_REGISTRY_ERRORS.has(
          decoded.name
        )
      ) {
        return true;
      }
    } catch {}
  }

  const text =
    errorText(error).toLowerCase();

  return [
    ...DETERMINISTIC_REGISTRY_ERRORS
  ].some(name =>
    text.includes(name.toLowerCase())
  ) || text.includes(
    "query already processed"
  );
}

function liveArtifactFallback(): LiveAuthorizationArtifact | null {
  const path =
    process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
    DEFAULT_LIVE_DEMO_FILE;

  if (!existsSync(path)) {
    return null;
  }

  const parsed =
    JSON.parse(
      readFileSync(path, "utf8")
    ) as LiveAuthorizationArtifact;

  if (parsed.version !== LIVE_DEMO_ARTIFACT_VERSION) {
    throw new Error(
      `Unsupported live authorization artifact version in ${path}: ${String(parsed.version)}`
    );
  }

  return parsed;
}

async function main(): Promise<void> {
  const creditcoin =
    resolveNetwork(
      "creditcoin-testnet"
    );

  const sepolia =
    resolveNetwork("sepolia");

  const deploymentConfig =
    resolveLiveDeploymentConfig();

  const sourceChainKey =
    positiveIntegerValue(
      "SOURCE_CHAIN_KEY",
      deploymentConfig.sourceChainKey ??
        requiredEnv("SOURCE_CHAIN_KEY")
    );

  const liveArtifact =
    liveArtifactFallback();

  const sourceTransactionHash =
    process.env.SOURCE_CHAIN_TXN_HASH?.trim() ||
    liveArtifact?.source.transactionHash;

  if (!sourceTransactionHash) {
    throw new Error(
      "Missing SOURCE_CHAIN_TXN_HASH and no build/live-authorization.json fallback is available"
    );
  }

  const sourceContract =
    getAddress(
      process.env.AUTHORIZATION_SOURCE_ADDRESS?.trim() ||
      liveArtifact?.source.authorizationSource ||
      deploymentConfig.authorizationSource ||
      requiredEnv(
        "AUTHORIZATION_SOURCE_ADDRESS"
      )
    );

  if (
    liveArtifact &&
    getAddress(liveArtifact.source.authorizationSource) !==
      sourceContract
  ) {
    throw new Error(
      "AUTHORIZATION_SOURCE_ADDRESS does not match the live authorization artifact"
    );
  }

  if (
    deploymentConfig.authorizationSource &&
    getAddress(deploymentConfig.authorizationSource) !==
      sourceContract
  ) {
    throw new Error(
      "Live authorization source does not match build/live-deployment.json"
    );
  }

  const registryAddress =
    getAddress(
      deploymentConfig.registryAddress ??
        requiredEnv(
          "AGENTFIREWALL_REGISTRY_ADDRESS"
        )
    );

  const sourceRpcUrl =
    trustedRpcForEnforcement(sepolia).url;

  const creditcoinRpcUrl =
    trustedRpcForEnforcement(creditcoin).url;

  const proofBuilderUrl =
    process.env.CREDITCOIN_PROOF_BUILDER_URL?.trim() ||
    "https://prover.cc3-testnet.creditcoin.network/";

  const sourceProvider =
    new JsonRpcProvider(
      sourceRpcUrl
    );

  const creditcoinProvider =
    new JsonRpcProvider(
      creditcoinRpcUrl
    );

  const [
    sourceNetwork,
    creditcoinNetwork
  ] = await Promise.all([
    sourceProvider.getNetwork(),
    creditcoinProvider.getNetwork()
  ]);

  if (sourceNetwork.chainId !== sepolia.chainId) {
    throw new Error(
      `Source RPC chain mismatch: expected Sepolia ${sepolia.chainId}, got ${sourceNetwork.chainId}`
    );
  }

  if (creditcoinNetwork.chainId !== creditcoin.chainId) {
    throw new Error(
      `Creditcoin chain mismatch: ${creditcoinNetwork.chainId}`
    );
  }

  const receipt =
    await sourceProvider.getTransactionReceipt(
      sourceTransactionHash
    );

  if (!receipt) {
    throw new Error(
      `Source transaction ${sourceTransactionHash} was not found or is not mined`
    );
  }

  if (receipt.status !== 1) {
    throw new Error(
      `source transaction failed: ${sourceTransactionHash}`
    );
  }

  const evidence =
    parseTrustedAuthorizationEvidence(
      receipt.logs.map((log: (typeof receipt.logs)[number]) => ({
        address: log.address,
        topics: log.topics,
        data: log.data,
        index: log.index
      })),
      sourceContract
    );

  validateSourceAuthorizationEvidence(
    evidence,
    sourceNetwork.chainId,
    sourceContract
  );

  const sourceCode =
    await sourceProvider.getCode(
      sourceContract
    );

  if (sourceCode === "0x") {
    throw new Error(
      `Authorization source ${sourceContract} has no deployed bytecode on Sepolia`
    );
  }

  const sourceReadContract =
    new Contract(
      sourceContract,
      AUTHORIZATION_SOURCE_ABI,
      sourceProvider
    );

  const [
    sourceCommitmentDomain,
    sourceIdDomain
  ] = await Promise.all([
    sourceReadContract.AUTHORIZATION_COMMITMENT_DOMAIN(),
    sourceReadContract.AUTHORIZATION_ID_DOMAIN()
  ]);

  if (
    String(sourceCommitmentDomain).toLowerCase() !==
    AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase()
  ) {
    throw new Error(
      `Authorization source commitment domain mismatch: ${String(sourceCommitmentDomain)}`
    );
  }

  if (
    String(sourceIdDomain).toLowerCase() !==
    AUTHORIZATION_ID_DOMAIN.toLowerCase()
  ) {
    throw new Error(
      `Authorization source id domain mismatch: ${String(sourceIdDomain)}`
    );
  }

  const creditcoinSecurityBlock =
    await creditcoinProvider.getBlock("latest");

  if (!creditcoinSecurityBlock?.hash) {
    throw new Error(
      "Unable to obtain Creditcoin chain time before semantic ingest"
    );
  }

  if (
    BigInt(evidence.validUntil) <=
    BigInt(creditcoinSecurityBlock.timestamp)
  ) {
    throw new Error(
      `source authorization expired at ${evidence.validUntil}`
    );
  }

  console.log(
    `[ATTESTCOIN] Waiting for Proof Builder attestation/proof for chainKey ${sourceChainKey}, block ${receipt.blockNumber}...`
  );

  const proof =
    await fetchAttestcoinProof({
      proofBuilderUrl,
      chainKey: sourceChainKey,
      transactionHash: sourceTransactionHash
    });

  const transactionIndex =
    assertProofMatchesSourceReceipt({
      proofChainKey:
        proof.chainKey,
      expectedChainKey:
        sourceChainKey,
      proofHeaderNumber:
        proof.headerNumber,
      receiptBlockNumber:
        receipt.blockNumber,
      siblings:
        proof.merkleProof.siblings,
      receiptTransactionIndex:
        receipt.index
    });

  const preflightVerified =
    await verifyAttestcoinProof(
      creditcoinProvider,
      proof
    );

  if (!preflightVerified) {
    throw new Error(
      "Creditcoin native BlockProver preflight returned false"
    );
  }

  const registryCode =
    await creditcoinProvider.getCode(
      registryAddress
    );

  if (registryCode === "0x") {
    throw new Error(
      `Semantic registry ${registryAddress} has no deployed bytecode on Creditcoin CC3`
    );
  }

  const registryReadContract =
    new Contract(
      registryAddress,
      VERIFIED_AUTHORIZATION_REGISTRY_ABI,
      creditcoinProvider
    );

  const [
    registryChainKey,
    registrySourceChainId,
    registrySource,
    registryCommitmentDomain,
    registryIdDomain
  ] = await Promise.all([
    registryReadContract.trustedSourceChainKey(),
    registryReadContract.trustedSourceChainId(),
    registryReadContract.trustedAuthorizationSource(),
    registryReadContract.AUTHORIZATION_COMMITMENT_DOMAIN(),
    registryReadContract.AUTHORIZATION_ID_DOMAIN()
  ]);

  validateSemanticRegistryTrustAnchors(
    {
      trustedSourceChainKey:
        registryChainKey,
      trustedSourceChainId:
        registrySourceChainId,
      trustedAuthorizationSource:
        String(registrySource),
      authorizationCommitmentDomain:
        String(registryCommitmentDomain),
      authorizationIdDomain:
        String(registryIdDomain)
    },
    {
      sourceChainKey,
      sourceChainId:
        sourceNetwork.chainId,
      authorizationSource:
        sourceContract
    }
  );

  const wallet =
    new Wallet(
      requiredEnv(
        "AGENTFIREWALL_TESTNET_PRIVATE_KEY"
      ),
      creditcoinProvider
    );

  const registry =
    registryReadContract.connect(
      wallet
    ) as Contract;

  const args = [
    proof.chainKey,
    proof.headerNumber,
    proof.txBytes,
    proof.merkleProof.root,
    proof.merkleProof.siblings,
    proof.continuityProof.lowerEndpointDigest,
    proof.continuityProof.roots
  ] as const;

  let gasLimit: bigint;

  try {
    const estimate =
      await registry.submitVerifiedAuthorization.estimateGas(
        ...args
      );

    gasLimit =
      estimate +
      estimate / 2n +
      100_000n;
  } catch (error) {
    if (deterministicSemanticFailure(error)) {
      throw error;
    }

    const configured =
      process.env.CC3_SEMANTIC_GAS_LIMIT?.trim();

    gasLimit =
      configured && /^\d+$/.test(configured)
        ? BigInt(configured)
        : 1_500_000n;

    console.warn(
      `[ATTESTCOIN] Gas estimation was inconclusive (${errorText(error)}). Using ${gasLimit} gas.`
    );
  }

  const tx =
    await registry.submitVerifiedAuthorization(
      ...args,
      {
        gasLimit
      }
    );

  const cc3Receipt =
    await tx.wait();

  if (
    !cc3Receipt ||
    cc3Receipt.status !== 1
  ) {
    throw new Error(
      `Creditcoin semantic registry transaction ${tx.hash} did not succeed`
    );
  }

  const [
    record,
    evidenceRecord
  ] = await Promise.all([
    registry.getAuthorization(
      evidence.authorizationId
    ),
    registry.getAuthorizationEvidence(
      evidence.authorizationId
    )
  ]);

  const normalizedRecord = {
    commitment:
      String(record.commitment).toLowerCase(),
    sourceChainKey:
      BigInt(record.sourceChainKey).toString(),
    sourceBlockNumber:
      BigInt(record.sourceBlockNumber).toString(),
    transactionIndex:
      BigInt(record.transactionIndex).toString(),
    validUntil:
      BigInt(record.validUntil).toString(),
    verified:
      Boolean(record.verified)
  };

  if (!normalizedRecord.verified) {
    throw new Error(
      "Semantic registry write succeeded but getAuthorization is not verified"
    );
  }

  if (
    normalizedRecord.commitment !==
    evidence.commitment.toLowerCase()
  ) {
    throw new Error(
      "Semantic registry commitment differs from the source AuthorizationPublished event"
    );
  }

  if (
    normalizedRecord.validUntil !==
    evidence.validUntil
  ) {
    throw new Error(
      "Semantic registry expiry differs from the source AuthorizationPublished event"
    );
  }

  if (
    normalizedRecord.transactionIndex !==
    transactionIndex.toString()
  ) {
    throw new Error(
      "Semantic registry transaction index differs from Merkle laterality"
    );
  }

  const expectedTransactionKey =
    computeProofTransactionKey(
      proof.chainKey,
      proof.headerNumber,
      transactionIndex
    ).toLowerCase();

  const expectedProvenTransactionHash =
    keccak256(proof.txBytes).toLowerCase();

  const normalizedEvidenceRecord = {
    commitment:
      String(evidenceRecord.commitment).toLowerCase(),
    sourceChainKey:
      BigInt(evidenceRecord.sourceChainKey).toString(),
    sourceBlockNumber:
      BigInt(evidenceRecord.sourceBlockNumber).toString(),
    transactionIndex:
      BigInt(evidenceRecord.transactionIndex).toString(),
    validUntil:
      BigInt(evidenceRecord.validUntil).toString(),
    sourceSender:
      getAddress(evidenceRecord.sourceSender),
    transactionKey:
      String(evidenceRecord.transactionKey).toLowerCase(),
    provenTransactionHash:
      String(evidenceRecord.provenTransactionHash).toLowerCase(),
    verified:
      Boolean(evidenceRecord.verified)
  };

  if (
    !normalizedEvidenceRecord.verified ||
    normalizedEvidenceRecord.commitment !== evidence.commitment.toLowerCase() ||
    normalizedEvidenceRecord.sourceChainKey !== proof.chainKey.toString() ||
    normalizedEvidenceRecord.sourceBlockNumber !== proof.headerNumber.toString() ||
    normalizedEvidenceRecord.transactionIndex !== transactionIndex.toString() ||
    normalizedEvidenceRecord.validUntil !== evidence.validUntil ||
    normalizedEvidenceRecord.sourceSender !== getAddress(evidence.sender) ||
    normalizedEvidenceRecord.transactionKey !== expectedTransactionKey ||
    normalizedEvidenceRecord.provenTransactionHash !== expectedProvenTransactionHash
  ) {
    throw new Error(
      "registry provenance does not match the source proof"
    );
  }

  if (liveArtifact) {
    const artifactPath =
      process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
      DEFAULT_LIVE_DEMO_FILE;

    liveArtifact.creditcoin = {
      registryAddress,
      transactionHash: tx.hash,
      blockNumber:
        cc3Receipt.blockNumber.toString(),
      sourceChainKey:
        normalizedEvidenceRecord.sourceChainKey,
      sourceBlockNumber:
        normalizedEvidenceRecord.sourceBlockNumber,
      transactionIndex:
        normalizedEvidenceRecord.transactionIndex,
      transactionKey:
        normalizedEvidenceRecord.transactionKey,
      provenTransactionHash:
        normalizedEvidenceRecord.provenTransactionHash,
      proofPreflightVerified:
        true
    };

    writeFileSync(
      artifactPath,
      `${JSON.stringify(liveArtifact, null, 2)}\n`,
      "utf8"
    );
  }

  console.log(
    JSON.stringify(
      {
        semanticAuthorizationVerified: true,
        source: {
          chain: "Sepolia",
          chainId:
            sourceNetwork.chainId.toString(),
          chainKey:
            sourceChainKey.toString(),
          authorizationSource:
            sourceContract,
          transactionHash:
            sourceTransactionHash,
          blockNumber:
            receipt.blockNumber,
          authorizationId:
            evidence.authorizationId,
          commitment:
            evidence.commitment,
          sender:
            evidence.sender,
          validUntil:
            evidence.validUntil
        },
        proof: {
          headerNumber:
            proof.headerNumber.toString(),
          transactionIndex:
            transactionIndex.toString(),
          preflightVerified: true
        },
        creditcoin: {
          chainId:
            creditcoinNetwork.chainId.toString(),
          registry:
            registryAddress,
          transactionHash:
            tx.hash,
          blockNumber:
            cc3Receipt.blockNumber,
          record:
            normalizedRecord,
          provenance:
            normalizedEvidenceRecord
        }
      },
      null,
      2
    )
  );
}

main().catch(
  error => {
    console.error(
      error instanceof Error
        ? error.message
        : error
    );
    process.exitCode = 1;
  }
);
