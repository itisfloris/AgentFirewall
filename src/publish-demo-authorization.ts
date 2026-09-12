import {
  Contract,
  JsonRpcProvider,
  Wallet,
  getAddress,
  keccak256
} from "ethers";

import {
  mkdirSync,
  writeFileSync
} from "node:fs";

import {
  dirname
} from "node:path";

import {
  AUTHORIZATION_SOURCE_ABI
} from "./attestcoin-b2.js";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN,
  AUTHORIZATION_ID_DOMAIN,
  parseTrustedAuthorizationEvidence,
  validateSourceAuthorizationEvidence
} from "./semantic-registry.js";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  buildNativeLiveDemoPlan,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

import {
  requireEvidenceSourceVersion
} from "./source-version.js";

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

function validitySeconds(): bigint {
  const raw =
    process.env.AGENTFIREWALL_DEMO_VALIDITY_SECONDS?.trim() ??
    "3600";

  if (!/^\d+$/.test(raw)) {
    throw new Error(
      "AGENTFIREWALL_DEMO_VALIDITY_SECONDS must be an unsigned integer"
    );
  }

  return BigInt(raw);
}

async function main(): Promise<void> {
  const sourceVersion =
    requireEvidenceSourceVersion();

  const sepolia =
    resolveNetwork("sepolia");

  const rpcUrl =
    trustedRpcForEnforcement(sepolia).url;

  const provider =
    new JsonRpcProvider(rpcUrl);

  try {
    const detected =
      await provider.getNetwork();

    if (detected.chainId !== sepolia.chainId) {
      throw new Error(
        `expected Sepolia ${sepolia.chainId}, got ${detected.chainId}`
      );
    }

    const wallet =
      new Wallet(
        requiredEnv(
          "AGENTFIREWALL_TESTNET_PRIVATE_KEY"
        ),
        provider
      );

    const deploymentConfig =
      resolveLiveDeploymentConfig();

    const sourceAddress =
      getAddress(
        deploymentConfig.authorizationSource ??
          requiredEnv(
            "AUTHORIZATION_SOURCE_ADDRESS"
          )
      );

    const sourceCode =
      await provider.getCode(
        sourceAddress
      );

    if (sourceCode === "0x") {
      throw new Error(
        `No AuthorizationSource bytecode at ${sourceAddress} on Sepolia`
      );
    }

    const source =
      new Contract(
        sourceAddress,
        AUTHORIZATION_SOURCE_ABI,
        wallet
      );

    const [
      commitmentDomain,
      idDomain
    ] = await Promise.all([
      source.AUTHORIZATION_COMMITMENT_DOMAIN(),
      source.AUTHORIZATION_ID_DOMAIN()
    ]);

    if (
      String(commitmentDomain).toLowerCase() !==
        AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase() ||
      String(idDomain).toLowerCase() !==
        AUTHORIZATION_ID_DOMAIN.toLowerCase()
    ) {
      throw new Error(
        "AuthorizationSource domain mismatch"
      );
    }

    const recipient =
      getAddress(
        process.env.AGENTFIREWALL_DEMO_RECIPIENT?.trim() ||
        wallet.address
      );

    const securityBlock =
      await provider.getBlock("latest");

    if (!securityBlock?.hash) {
      throw new Error(
        "Unable to obtain a complete Sepolia block for authorization creation time"
      );
    }

    const [
      currentNonce,
      targetCode
    ] = await Promise.all([
      provider.getTransactionCount(
        wallet.address,
        "pending"
      ),
      provider.getCode(
        recipient,
        securityBlock.number
      )
    ]);

    const plan =
      buildNativeLiveDemoPlan({
        sender: wallet.address,
        recipient,
        currentSepoliaNonce:
          currentNonce,
        targetCodeHash:
          keccak256(targetCode),
        nowSeconds:
          securityBlock.timestamp,
        validitySeconds:
          validitySeconds(),
        amountWei: 1n
      });

    const expectedCommitment =
      String(
        await source.computeCommitment(
          plan.authorization
        )
      ).toLowerCase();

    const staticResult =
      await source.publishAuthorization.staticCall(
        plan.authorization
      ) as readonly [string, string];

    const expectedAuthorizationId =
      String(staticResult[0]).toLowerCase();

    if (
      String(staticResult[1]).toLowerCase() !==
      expectedCommitment
    ) {
      throw new Error(
        "AuthorizationSource static publish commitment does not match computeCommitment()"
      );
    }

    console.log(
      "Publishing one sender-authenticated Authorization.v3 on Sepolia..."
    );
    console.log(
      `wallet=${wallet.address} publishNonce=${currentNonce} authorizedExecutionNonce=${plan.authorization.executionNonce}`
    );

    const transaction =
      await source.publishAuthorization(
        plan.authorization
      );

    const receipt =
      await transaction.wait();

    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `AuthorizationSource publish transaction failed: ${transaction.hash}`
      );
    }

    const evidence =
      parseTrustedAuthorizationEvidence(
        receipt.logs.map((log: (typeof receipt.logs)[number]) => ({
          address: log.address,
          topics: [...log.topics],
          data: log.data,
          index: log.index
        })),
        sourceAddress
      );

    validateSourceAuthorizationEvidence(
      evidence,
      sepolia.chainId,
      sourceAddress
    );

    if (
      evidence.authorizationId !==
        expectedAuthorizationId ||
      evidence.commitment !==
        expectedCommitment
    ) {
      throw new Error(
        "Mined AuthorizationPublished evidence differs from the preflighted authorization id/commitment"
      );
    }

    if (
      evidence.executionNonce !==
        plan.authorization.executionNonce ||
      evidence.sender !== wallet.address ||
      evidence.target !== recipient
    ) {
      throw new Error(
        "Mined AuthorizationPublished execution semantics differ from the demo plan"
      );
    }

    const artifactPath =
      process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
      DEFAULT_LIVE_DEMO_FILE;

    const artifact: LiveAuthorizationArtifact = {
      version:
        LIVE_DEMO_ARTIFACT_VERSION,
      createdAt:
        new Date().toISOString(),
      build: {
        sourceId:
          sourceVersion.sourceId,
        sourceKind:
          sourceVersion.sourceKind,
        ...(sourceVersion.sourceCommit
          ? {
              sourceCommit:
                sourceVersion.sourceCommit
            }
          : {}),
        ...(sourceVersion.treeClean !== null
          ? {
              sourceTreeClean:
                sourceVersion.treeClean
            }
          : {})
      },
      source: {
        network: "sepolia",
        chainId:
          sepolia.chainId.toString(),
        authorizationSource:
          sourceAddress,
        transactionHash:
          transaction.hash,
        blockNumber:
          receipt.blockNumber.toString(),
        authorizationId:
          evidence.authorizationId,
        commitment:
          evidence.commitment,
        sourceAuthorizationNonce:
          evidence.nonce,
        transactionIndex:
          receipt.index.toString()
      },
      execution: {
        declaredIntent:
          plan.declaredIntent,
        transaction:
          plan.transaction,
        mutatedTransaction:
          plan.mutatedTransaction
      }
    };

    mkdirSync(
      dirname(artifactPath),
      {
        recursive: true
      }
    );

    writeFileSync(
      artifactPath,
      `${JSON.stringify(artifact, null, 2)}\n`,
      "utf8"
    );

    console.log(
      JSON.stringify(
        {
          sourceTransactionHash:
            transaction.hash,
          sourceBlockNumber:
            receipt.blockNumber.toString(),
          authorizationId:
            evidence.authorizationId,
          commitment:
            evidence.commitment,
          validUntil:
            evidence.validUntil,
          authorizedExecutionNonce:
            evidence.executionNonce,
          target:
            evidence.target,
          targetCodeHash:
            evidence.targetCodeHash,
          artifact:
            artifactPath
        },
        null,
        2
      )
    );

    console.log(
      "NEXT: use this source transaction with `npm run attestcoin:ingest-authorization`, then run `npm run demo:verified-live`."
    );
  } finally {
    provider.destroy();
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
