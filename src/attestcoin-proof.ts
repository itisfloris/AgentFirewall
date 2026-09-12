import {
  JsonRpcProvider
} from "ethers";

import {
  fetchAttestcoinProof,
  verifyAttestcoinProof
} from "./attestcoin-native.js";

import {
  assertProofMatchesSourceReceipt
} from "./attestcoin-b2.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

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

function positiveIntegerEnv(
  name: string
): number {
  const raw = requiredEnv(name);

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

async function main(): Promise<void> {
  const creditcoin =
    resolveNetwork(
      "creditcoin-testnet"
    );

  const sepolia =
    resolveNetwork("sepolia");

  const creditcoinRpcUrl =
    trustedRpcForEnforcement(creditcoin).url;

  const sourceRpcUrl =
    trustedRpcForEnforcement(sepolia).url;

  const proofBuilderUrl =
    process.env.CREDITCOIN_PROOF_BUILDER_URL?.trim() ||
    "https://prover.cc3-testnet.creditcoin.network/";

  const chainKey =
    positiveIntegerEnv(
      "SOURCE_CHAIN_KEY"
    );

  const transactionHash =
    requiredEnv(
      "SOURCE_CHAIN_TXN_HASH"
    );

  const creditcoinProvider =
    new JsonRpcProvider(
      creditcoinRpcUrl
    );

  const creditcoinNetwork =
    await creditcoinProvider.getNetwork();

  if (
    creditcoinNetwork.chainId !==
    creditcoin.chainId
  ) {
    throw new Error(
      `Creditcoin chain mismatch: ${creditcoinNetwork.chainId}`
    );
  }

  const sourceProvider =
    new JsonRpcProvider(sourceRpcUrl);

  const sourceNetwork =
    await sourceProvider.getNetwork();

  if (
    sourceNetwork.chainId !==
    sepolia.chainId
  ) {
    throw new Error(
      `Source RPC chain mismatch: expected Sepolia ${sepolia.chainId}, got ${sourceNetwork.chainId}`
    );
  }

  const receipt =
    await sourceProvider.getTransactionReceipt(
      transactionHash
    );

  if (!receipt) {
    throw new Error(
      `Source transaction ${transactionHash} was not found or is not mined`
    );
  }

  if (receipt.status !== 1) {
    throw new Error(
      `source transaction failed: ${transactionHash}`
    );
  }

  console.log(
    `[ATTESTCOIN] Waiting for Proof Builder attestation/proof for chainKey ${chainKey}, block ${receipt.blockNumber}...`
  );

  const proof =
    await fetchAttestcoinProof({
      proofBuilderUrl,
      chainKey,
      transactionHash
    });

  if (
    proof.chainKey !== BigInt(chainKey)
  ) {
    throw new Error(
      `Proof chain mismatch: expected ${chainKey}, got ${proof.chainKey}`
    );
  }

  const transactionIndex =
    assertProofMatchesSourceReceipt({
      proofChainKey: proof.chainKey,
      expectedChainKey: chainKey,
      proofHeaderNumber: proof.headerNumber,
      receiptBlockNumber: receipt.blockNumber,
      siblings: proof.merkleProof.siblings,
      receiptTransactionIndex: receipt.index
    });

  const verified =
    await verifyAttestcoinProof(
      creditcoinProvider,
      proof
    );

  if (!verified) {
    throw new Error(
      "Creditcoin native BlockProver verification returned false"
    );
  }

  console.log(
    JSON.stringify(
      {
        proofVerified: true,
        verificationSurface:
          "Creditcoin native BlockProver 0x0000000000000000000000000000000000000FD2",
        proofAcquisition:
          "Creditcoin Proof Builder HTTP API /api/v1/proof-by-tx",
        creditcoinChainId:
          creditcoinNetwork.chainId.toString(),
        sourceChainKey:
          proof.chainKey.toString(),
        sourceChainId:
          sourceNetwork.chainId.toString(),
        sourceTransactionHash:
          transactionHash,
        sourceBlockNumber:
          receipt.blockNumber,
        proofHeaderNumber:
          proof.headerNumber.toString(),
        proofTransactionIndex:
          transactionIndex.toString(),
        proofBuilderUrl
      },
      null,
      2
    )
  );
}

main().catch(
  (error) => {
    console.error(
      error instanceof Error
        ? error.message
        : error
    );
    process.exitCode = 1;
  }
);
