import {
  Interface,
  JsonRpcProvider,
  getAddress,
  keccak256,
  toBeHex
} from "ethers";

import {
  readFileSync
} from "node:fs";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  DEFAULT_LIVE_EVIDENCE_FILE,
  historicalEvidenceMatchesArtifacts,
  type LiveJudgeEvidence
} from "./live-evidence.js";

import {
  loadLiveDeploymentArtifact,
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

import {
  parseTrustedAuthorizationEvidence,
  validateSourceAuthorizationEvidence,
  verifiedAuthorizationRegistryInterface
} from "./semantic-registry.js";

import {
  calculateTransactionIndex,
  computeProofTransactionKey
} from "./attestcoin-b2.js";

import {
  CreditcoinAuthorizationRegistryReader,
  normalizeSemanticRegistryTrustConfig
} from "./verified-preflight.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  redactRpcEndpoint,
  sanitizeRpcError
} from "./rpc-security.js";

const ZERO_BYTES32 =
  `0x${"00".repeat(32)}`;

function sameHex(
  left: string,
  right: string
): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function assertEqual(
  actual: unknown,
  expected: unknown,
  field: string
): void {
  if (String(actual) !== String(expected)) {
    throw new Error(
      `${field} mismatch: expected ${String(expected)}, got ${String(actual)}`
    );
  }
}

function assertHexEqual(
  actual: string,
  expected: string,
  field: string
): void {
  if (!sameHex(actual, expected)) {
    throw new Error(
      `${field} mismatch: expected ${expected}, got ${actual}`
    );
  }
}

async function codeAt(
  provider: JsonRpcProvider,
  address: string,
  blockNumber: bigint | number | string
): Promise<string> {
  const value = await provider.send(
    "eth_getCode",
    [address, toBeHex(BigInt(blockNumber))]
  );

  if (typeof value !== "string") {
    throw new Error(
      "eth_getCode returned a non-string value"
    );
  }

  return value;
}

async function verifySource(
  provider: JsonRpcProvider,
  artifact: LiveAuthorizationArtifact,
  deployment: NonNullable<ReturnType<typeof loadLiveDeploymentArtifact>>
) {
  if (!deployment.source) {
    throw new Error(
      "Live deployment artifact has no Sepolia AuthorizationSource"
    );
  }

  const receipt =
    await provider.getTransactionReceipt(
      artifact.source.transactionHash
    );

  if (!receipt) {
    throw new Error(
      "Sepolia source receipt is unavailable"
    );
  }

  if (receipt.status !== 1) {
    throw new Error(
      `Sepolia source receipt status is ${String(receipt.status)}, expected 1`
    );
  }

  assertEqual(
    receipt.blockNumber,
    artifact.source.blockNumber,
    "Sepolia source block"
  );

  if (artifact.source.transactionIndex !== undefined) {
    assertEqual(
      receipt.index,
      artifact.source.transactionIndex,
      "Sepolia source transaction index"
    );
  }

  if (!receipt.to) {
    throw new Error(
      "Sepolia source transaction has no destination"
    );
  }

  assertHexEqual(
    getAddress(receipt.to),
    getAddress(deployment.source.address),
    "Sepolia source transaction destination"
  );

  const sourceCode = await codeAt(
    provider,
    deployment.source.address,
    artifact.source.blockNumber
  );

  if (sourceCode === "0x") {
    throw new Error(
      "AuthorizationSource had no code at the source block"
    );
  }

  assertHexEqual(
    keccak256(sourceCode),
    deployment.source.runtimeCodeHash,
    "AuthorizationSource historical runtime code hash"
  );

  const parsed =
    parseTrustedAuthorizationEvidence(
      receipt.logs.map(log => ({
        address: log.address,
        topics: log.topics,
        data: log.data,
        index: log.index
      })),
      deployment.source.address
    );

  validateSourceAuthorizationEvidence(
    parsed,
    deployment.source.chainId,
    deployment.source.address
  );

  assertHexEqual(
    parsed.authorizationId,
    artifact.source.authorizationId,
    "source AuthorizationId"
  );
  assertHexEqual(
    parsed.commitment,
    artifact.source.commitment,
    "source commitment"
  );

  return {
    receipt,
    parsed
  };
}

async function verifyCreditcoin(
  provider: JsonRpcProvider,
  artifact: LiveAuthorizationArtifact,
  evidence: LiveJudgeEvidence,
  deployment: NonNullable<ReturnType<typeof loadLiveDeploymentArtifact>>,
  creditcoinRpcUrl: string,
  creditcoinRpcLabel: string
) {
  if (!deployment.semanticRegistry || !artifact.creditcoin) {
    throw new Error(
      "Live artifacts do not contain the Creditcoin semantic registry"
    );
  }

  const receipt =
    await provider.getTransactionReceipt(
      artifact.creditcoin.transactionHash
    );

  if (!receipt) {
    throw new Error(
      "Creditcoin semantic-ingest receipt is unavailable"
    );
  }

  if (receipt.status !== 1) {
    throw new Error(
      `Creditcoin semantic-ingest receipt status is ${String(receipt.status)}, expected 1`
    );
  }

  assertEqual(
    receipt.blockNumber,
    artifact.creditcoin.blockNumber,
    "Creditcoin ingest block"
  );

  if (!receipt.to) {
    throw new Error(
      "Creditcoin semantic-ingest transaction has no destination"
    );
  }

  assertHexEqual(
    getAddress(receipt.to),
    getAddress(deployment.semanticRegistry.address),
    "Creditcoin ingest destination"
  );

  const ingestTransaction =
    await provider.getTransaction(
      artifact.creditcoin.transactionHash
    );

  if (!ingestTransaction?.to) {
    throw new Error(
      "Creditcoin semantic-ingest transaction is unavailable or has no destination"
    );
  }

  assertHexEqual(
    getAddress(ingestTransaction.to),
    getAddress(deployment.semanticRegistry.address),
    "Creditcoin ingest transaction destination"
  );

  const parsedIngest =
    verifiedAuthorizationRegistryInterface.parseTransaction({
      data: ingestTransaction.data,
      value: ingestTransaction.value
    });

  if (
    !parsedIngest ||
    parsedIngest.name !== "submitVerifiedAuthorization"
  ) {
    throw new Error(
      "Creditcoin evidence transaction is not submitVerifiedAuthorization"
    );
  }

  const proofChainKey = BigInt(parsedIngest.args[0]);
  const proofBlockHeight = BigInt(parsedIngest.args[1]);
  const encodedTransaction = String(parsedIngest.args[2]);
  const siblings = Array.from(parsedIngest.args[4] as ArrayLike<{ isLeft: boolean }>);
  const proofTransactionIndex =
    calculateTransactionIndex(siblings);
  const proofTransactionKey =
    computeProofTransactionKey(
      proofChainKey,
      proofBlockHeight,
      proofTransactionIndex
    );
  const provenEncodedTransactionHash =
    keccak256(encodedTransaction);

  assertEqual(
    proofChainKey.toString(),
    artifact.creditcoin.sourceChainKey,
    "Creditcoin ingest proof chainKey"
  );
  assertEqual(
    proofBlockHeight.toString(),
    artifact.creditcoin.sourceBlockNumber,
    "Creditcoin ingest proof block"
  );
  assertEqual(
    proofTransactionIndex.toString(),
    artifact.creditcoin.transactionIndex,
    "Creditcoin ingest proof transaction index"
  );
  assertHexEqual(
    proofTransactionKey,
    artifact.creditcoin.transactionKey,
    "Creditcoin ingest proof transaction key"
  );
  assertHexEqual(
    provenEncodedTransactionHash,
    artifact.creditcoin.provenTransactionHash,
    "Creditcoin ingest keccak256(encodedTransaction)"
  );

  const recordedTopic =
    verifiedAuthorizationRegistryInterface
      .getEvent("VerifiedAuthorizationRecorded")
      ?.topicHash;

  if (!recordedTopic) {
    throw new Error(
      "VerifiedAuthorizationRecorded event is missing from the registry ABI"
    );
  }

  const recordedLogs = receipt.logs.filter(log =>
    getAddress(log.address) ===
      getAddress(deployment.semanticRegistry!.address) &&
    log.topics[0]?.toLowerCase() ===
      recordedTopic.toLowerCase()
  );

  if (recordedLogs.length !== 1) {
    throw new Error(
      `expected one VerifiedAuthorizationRecorded event, got ${recordedLogs.length}`
    );
  }

  const parsedRecorded =
    verifiedAuthorizationRegistryInterface.parseLog({
      topics: [...recordedLogs[0].topics],
      data: recordedLogs[0].data
    });

  if (
    !parsedRecorded ||
    parsedRecorded.name !== "VerifiedAuthorizationRecorded"
  ) {
    throw new Error(
      "Unable to decode VerifiedAuthorizationRecorded event from the ingest receipt"
    );
  }

  assertHexEqual(
    String(parsedRecorded.args.authorizationId),
    artifact.source.authorizationId,
    "Creditcoin recorded AuthorizationId"
  );
  assertHexEqual(
    String(parsedRecorded.args.commitment),
    artifact.source.commitment,
    "Creditcoin recorded commitment"
  );
  assertHexEqual(
    getAddress(String(parsedRecorded.args.sourceSender)),
    getAddress(artifact.execution.declaredIntent.sender ?? ""),
    "Creditcoin recorded source sender"
  );
  assertEqual(
    BigInt(parsedRecorded.args.sourceChainKey).toString(),
    artifact.creditcoin.sourceChainKey,
    "Creditcoin recorded sourceChainKey"
  );
  assertEqual(
    BigInt(parsedRecorded.args.sourceBlockNumber).toString(),
    artifact.creditcoin.sourceBlockNumber,
    "Creditcoin recorded source block"
  );
  assertEqual(
    BigInt(parsedRecorded.args.transactionIndex).toString(),
    artifact.creditcoin.transactionIndex,
    "Creditcoin recorded transaction index"
  );
  assertHexEqual(
    String(parsedRecorded.args.transactionKey),
    artifact.creditcoin.transactionKey,
    "Creditcoin recorded transaction key"
  );
  assertHexEqual(
    String(parsedRecorded.args.provenTransactionHash),
    artifact.creditcoin.provenTransactionHash,
    "Creditcoin recorded keccak256(encodedTransaction)"
  );

  const trustConfig =
    normalizeSemanticRegistryTrustConfig(
      deployment.semanticRegistry.sourceChainKey,
      deployment.semanticRegistry.trustedAuthorizationSource
    );

  const reader =
    new CreditcoinAuthorizationRegistryReader(
      deployment.semanticRegistry.address,
      trustConfig,
      creditcoinRpcUrl,
      deployment.semanticRegistry.runtimeCodeHash,
      creditcoinRpcLabel
    );

  const record =
    await reader.getAuthorization(
      artifact.source.authorizationId
    );

  if (!record || record.verified !== true) {
    throw new Error(
      "Creditcoin registry does not currently contain the verified historical authorization"
    );
  }

  if (
    !historicalEvidenceMatchesArtifacts({
      deployment,
      artifact,
      evidence,
      registryRecord: record
    })
  ) {
    throw new Error(
      "Current Creditcoin registry record does not match bundled historical evidence"
    );
  }

  const richCall =
    verifiedAuthorizationRegistryInterface
      .encodeFunctionData(
        "getAuthorizationEvidence",
        [artifact.source.authorizationId]
      );

  if (
    !record.registrySnapshotBlockNumber ||
    !record.registrySnapshotBlockHash
  ) {
    throw new Error(
      "Creditcoin registry reader did not return its verified snapshot identity"
    );
  }

  const snapshotBlockNumber =
    BigInt(record.registrySnapshotBlockNumber);
  const snapshotTag = toBeHex(snapshotBlockNumber);
  const raw = await provider.send(
    "eth_call",
    [
      {
        to: deployment.semanticRegistry.address,
        data: richCall
      },
      snapshotTag
    ]
  );

  if (typeof raw !== "string") {
    throw new Error(
      "Creditcoin provenance eth_call returned a non-string result"
    );
  }

  const confirmedSnapshot =
    await provider.getBlock(Number(snapshotBlockNumber));

  if (
    !confirmedSnapshot?.hash ||
    !sameHex(
      confirmedSnapshot.hash,
      record.registrySnapshotBlockHash
    )
  ) {
    throw new Error(
      "Creditcoin registry snapshot changed while provenance was being re-verified"
    );
  }

  const rich =
    verifiedAuthorizationRegistryInterface
      .decodeFunctionResult(
        "getAuthorizationEvidence",
        raw
      );

  const richCommitment = String(rich[0]);
  const richSourceChainKey = BigInt(rich[1] as bigint).toString();
  const richSourceBlock = BigInt(rich[2] as bigint).toString();
  const richTransactionIndex = BigInt(rich[3] as bigint).toString();
  const richValidUntil = BigInt(rich[4] as bigint).toString();
  const richSourceSender = getAddress(String(rich[5]));
  const richTransactionKey = String(rich[6]);
  const richProvenEncodedTransactionHash = String(rich[7]);
  const richVerified = Boolean(rich[8]);

  if (
    !richVerified ||
    sameHex(richCommitment, ZERO_BYTES32)
  ) {
    throw new Error(
      "Creditcoin provenance record is not verified"
    );
  }

  assertHexEqual(
    richCommitment,
    artifact.source.commitment,
    "Creditcoin provenance commitment"
  );
  assertEqual(
    richSourceChainKey,
    artifact.creditcoin.sourceChainKey,
    "Creditcoin provenance sourceChainKey"
  );
  assertEqual(
    richSourceBlock,
    artifact.creditcoin.sourceBlockNumber,
    "Creditcoin provenance source block"
  );
  assertEqual(
    richTransactionIndex,
    artifact.creditcoin.transactionIndex,
    "Creditcoin provenance transaction index"
  );
  assertEqual(
    richValidUntil,
    artifact.execution.declaredIntent.validUntil,
    "Creditcoin provenance expiry"
  );
  assertHexEqual(
    richSourceSender,
    artifact.execution.declaredIntent.sender ?? "",
    "Creditcoin provenance source sender"
  );
  assertHexEqual(
    richTransactionKey,
    artifact.creditcoin.transactionKey,
    "Creditcoin proof transaction key"
  );
  assertHexEqual(
    richProvenEncodedTransactionHash,
    artifact.creditcoin.provenTransactionHash,
    "Creditcoin keccak256(encodedTransaction)"
  );

  return {
    receipt,
    record
  };
}

async function verifyExecution(
  provider: JsonRpcProvider,
  artifact: LiveAuthorizationArtifact,
  evidence: LiveJudgeEvidence
) {
  if (!artifact.executionResult || !evidence.execution) {
    return null;
  }

  const transaction =
    await provider.getTransaction(
      artifact.executionResult.transactionHash
    );
  const receipt =
    await provider.getTransactionReceipt(
      artifact.executionResult.transactionHash
    );

  if (!transaction || !receipt) {
    throw new Error(
      "Guarded historical execution transaction or receipt is unavailable"
    );
  }

  if (receipt.status !== 1) {
    throw new Error(
      `Guarded historical execution receipt status is ${String(receipt.status)}, expected 1`
    );
  }

  assertEqual(
    receipt.blockNumber,
    artifact.executionResult.blockNumber,
    "guarded execution block"
  );
  assertHexEqual(
    transaction.hash,
    evidence.execution.transactionHash,
    "guarded execution transaction hash"
  );

  const expected = artifact.execution.transaction;

  if (!expected.from || expected.nonce === undefined) {
    throw new Error(
      "Historical execution artifact is missing sender or nonce"
    );
  }

  if (!transaction.to) {
    throw new Error(
      "Guarded execution has no destination"
    );
  }

  assertHexEqual(
    transaction.from,
    expected.from,
    "guarded execution sender"
  );
  assertHexEqual(
    transaction.to,
    expected.to,
    "guarded execution destination"
  );
  assertEqual(
    transaction.nonce,
    expected.nonce,
    "guarded execution nonce"
  );
  assertEqual(
    transaction.value.toString(),
    expected.valueWei ?? "0",
    "guarded execution value"
  );
  assertHexEqual(
    transaction.data || "0x",
    expected.data || "0x",
    "guarded execution calldata"
  );

  return {
    transaction,
    receipt
  };
}

async function main(): Promise<void> {
  const artifactPath =
    process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
    DEFAULT_LIVE_DEMO_FILE;
  const evidencePath =
    process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
    DEFAULT_LIVE_EVIDENCE_FILE;

  const artifact = JSON.parse(
    readFileSync(artifactPath, "utf8")
  ) as LiveAuthorizationArtifact;
  const evidence = JSON.parse(
    readFileSync(evidencePath, "utf8")
  ) as LiveJudgeEvidence;
  const deployment =
    loadLiveDeploymentArtifact();

  if (
    artifact.version !== LIVE_DEMO_ARTIFACT_VERSION ||
    !deployment?.source ||
    !deployment.semanticRegistry
  ) {
    throw new Error(
      "Historical live deployment/authorization artifacts are incomplete"
    );
  }

  const resolved =
    resolveLiveDeploymentConfig();

  if (
    !resolved.registryRuntimeCodeHash ||
    !resolved.authorizationSourceRuntimeCodeHash
  ) {
    throw new Error(
      "Historical deployment is missing expected source/registry runtime code hashes"
    );
  }

  const sepolia = resolveNetwork("sepolia");
  const creditcoin = resolveNetwork("creditcoin-testnet");
  const sepoliaEndpoint = trustedRpcForEnforcement(sepolia);
  const creditcoinEndpoint = trustedRpcForEnforcement(creditcoin);

  const sepoliaProvider = new JsonRpcProvider(
    sepoliaEndpoint.url,
    Number(sepolia.chainId),
    { staticNetwork: true }
  );
  const creditcoinProvider = new JsonRpcProvider(
    creditcoinEndpoint.url,
    Number(creditcoin.chainId),
    { staticNetwork: true }
  );

  try {
    const [sepoliaNetwork, creditcoinNetwork] =
      await Promise.all([
        sepoliaProvider.getNetwork(),
        creditcoinProvider.getNetwork()
      ]);

    if (sepoliaNetwork.chainId !== sepolia.chainId) {
      throw new Error(
        `Sepolia RPC chain mismatch: ${sepoliaNetwork.chainId}`
      );
    }
    if (creditcoinNetwork.chainId !== creditcoin.chainId) {
      throw new Error(
        `Creditcoin RPC chain mismatch: ${creditcoinNetwork.chainId}`
      );
    }

    await verifySource(
      sepoliaProvider,
      artifact,
      deployment
    );
    await verifyCreditcoin(
      creditcoinProvider,
      artifact,
      evidence,
      deployment,
      creditcoinEndpoint.url,
      `${creditcoinEndpoint.source}@${redactRpcEndpoint(creditcoinEndpoint.url)}`
    );
    await verifyExecution(
      sepoliaProvider,
      artifact,
      evidence
    );

    const latest = await sepoliaProvider.getBlock("latest");
    const sender = artifact.execution.declaredIntent.sender;
    const expectedNonce = artifact.execution.declaredIntent.executionNonce;
    const validUntil = artifact.execution.declaredIntent.validUntil;

    if (!latest || !sender || !expectedNonce || !validUntil) {
      throw new Error(
        "Historical authorization lacks fields required for current-usability status"
      );
    }

    const pendingNonce =
      await sepoliaProvider.getTransactionCount(
        getAddress(sender),
        "pending"
      );
    const unexpired =
      BigInt(latest.timestamp) < BigInt(validUntil);
    const nonceStillPending =
      BigInt(pendingNonce) === BigInt(expectedNonce);

    console.log(
      JSON.stringify(
        {
          historicalLiveEvidenceVerified: true,
          authorizationChainWindowOpen:
            unexpired && nonceStillPending,
          authorizationCurrentlyUsable: false,
          currentUsability: {
            unexpired,
            nonceStillPending,
            guardedSignerDecision:
              "not-evaluated: a fresh execution request, fee envelope, chain snapshot, and trusted-controller EIP-712 approval are required"
          },
          rpc: {
            sepolia:
              `${sepoliaEndpoint.source}@${redactRpcEndpoint(sepoliaEndpoint.url)}`,
            creditcoin:
              `${creditcoinEndpoint.source}@${redactRpcEndpoint(creditcoinEndpoint.url)}`
          },
          authorizationId:
            artifact.source.authorizationId,
          sourceTransaction:
            evidence.source.transactionHash,
          creditcoinSemanticIngest:
            evidence.creditcoin.transactionHash,
          guardedHistoricalExecution:
            evidence.execution?.transactionHash ?? null,
          provenEncodedTransactionHash:
            evidence.creditcoin.provenTransactionHash,
          note:
            "provenEncodedTransactionHash is keccak256(encodedTransaction) from the Attestcoin proof payload; it is not presented as the canonical Ethereum transaction hash."
        },
        null,
        2
      )
    );
  } catch (error) {
    throw new Error(
      sanitizeRpcError(
        error,
        [
          sepoliaEndpoint.url,
          creditcoinEndpoint.url
        ]
      )
    );
  } finally {
    sepoliaProvider.destroy();
    creditcoinProvider.destroy();
  }
}

main().catch(error => {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
});
