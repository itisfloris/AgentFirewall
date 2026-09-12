import {
  Wallet,
  getAddress
} from "ethers";

import {
  readFileSync,
  writeFileSync
} from "node:fs";

import {
  controllerApprovalTypedDataV2,
  verifyControllerApprovalV2,
  type ControllerApprovalMessage
} from "./controller-approval.js";

import type {
  FeeSafetyPolicy
} from "./guarded-signer.js";

import {
  DEFAULT_LIVE_DEMO_FILE,
  LIVE_DEMO_ARTIFACT_VERSION,
  type LiveAuthorizationArtifact
} from "./live-demo.js";

function requiredEnv(
  name: string
): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `${name} is required to create the independent controller approval`
    );
  }

  return value;
}


function feePolicyFromEnv(): FeeSafetyPolicy {
  return {
    maxGasLimit: requiredEnv("AGENTFIREWALL_MAX_GAS_LIMIT"),
    maxFeePerGasWei: requiredEnv("AGENTFIREWALL_MAX_FEE_PER_GAS_WEI"),
    maxPriorityFeePerGasWei: requiredEnv("AGENTFIREWALL_MAX_PRIORITY_FEE_PER_GAS_WEI"),
    maxTotalFeeWei: requiredEnv("AGENTFIREWALL_MAX_TOTAL_FEE_WEI")
  };
}

function loadArtifact(): {
  path: string;
  artifact: LiveAuthorizationArtifact;
} {
  const path =
    process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
    DEFAULT_LIVE_DEMO_FILE;

  const artifact = JSON.parse(
    readFileSync(path, "utf8")
  ) as LiveAuthorizationArtifact;

  if (artifact.version !== LIVE_DEMO_ARTIFACT_VERSION) {
    throw new Error(
      `Unsupported live authorization artifact version: ${String(artifact.version)}`
    );
  }

  if (!artifact.creditcoin) {
    throw new Error(
      "Creditcoin proof record missing; run the semantic ingest before controller approval"
    );
  }

  return { path, artifact };
}

async function main(): Promise<void> {
  const { path, artifact } = loadArtifact();
  const creditcoin = artifact.creditcoin;

  if (!creditcoin) {
    throw new Error(
      "Creditcoin proof record missing; run the semantic ingest before controller approval"
    );
  }

  const controller = new Wallet(
    requiredEnv("AGENTFIREWALL_CONTROLLER_PRIVATE_KEY")
  );
  const executor = getAddress(
    artifact.execution.declaredIntent.sender ?? ""
  );

  if (controller.address === executor) {
    throw new Error(
      "Controller and executor must use different keys"
    );
  }

  const configuredController =
    process.env.AGENTFIREWALL_TRUSTED_CONTROLLER?.trim();

  if (
    configuredController &&
    getAddress(configuredController) !== controller.address
  ) {
    throw new Error(
      `AGENTFIREWALL_TRUSTED_CONTROLLER ${getAddress(configuredController)} does not match controller private key ${controller.address}`
    );
  }

  const message: ControllerApprovalMessage = {
    authorizationId:
      artifact.source.authorizationId,
    commitment:
      artifact.source.commitment,
    executor,
    executionChainId:
      artifact.execution.declaredIntent.executionChainId,
    executionNonce:
      artifact.execution.declaredIntent.executionNonce ?? "",
    validUntil:
      artifact.execution.declaredIntent.validUntil ?? "",
    registryAddress:
      creditcoin.registryAddress,
    sourceChainKey:
      creditcoin.sourceChainKey
  };

  const feePolicy = feePolicyFromEnv();
  const typed = controllerApprovalTypedDataV2(
    message,
    feePolicy
  );
  const signature = await controller.signTypedData(
    typed.domain,
    typed.types,
    typed.message
  );

  verifyControllerApprovalV2(
    controller.address,
    message,
    feePolicy,
    signature
  );

  artifact.controllerApproval = {
    generatedAt: new Date().toISOString(),
    controller: controller.address,
    executor,
    signature,
    message,
    version: "2",
    feePolicy
  };

  writeFileSync(
    path,
    `${JSON.stringify(artifact, null, 2)}\n`,
    "utf8"
  );

  console.log(
    JSON.stringify(
      {
        controller: controller.address,
        executor,
        authoritySeparated: true,
        authorizationId:
          artifact.source.authorizationId,
        artifact: path
      },
      null,
      2
    )
  );
}

main().catch(error => {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
});
