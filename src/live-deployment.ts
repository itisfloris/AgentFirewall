import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync
} from "node:fs";

import {
  dirname
} from "node:path";

import {
  getAddress
} from "ethers";

export const LIVE_DEPLOYMENT_ARTIFACT_VERSION =
  "AgentFirewall.LiveDeployment.v1";

export const DEFAULT_LIVE_DEPLOYMENT_FILE =
  "build/live-deployment.json";

export type LiveDeploymentArtifact = {
  version: typeof LIVE_DEPLOYMENT_ARTIFACT_VERSION;
  updatedAt: string;
  source?: {
    network: "sepolia";
    chainId: string;
    address: string;
    runtimeCodeHash: string;
    deploymentTx: string | null;
  };
  semanticRegistry?: {
    network: "creditcoin-testnet";
    chainId: string;
    sourceChainKey: string;
    sourceChainId: string;
    trustedAuthorizationSource: string;
    decoderMode: "inlined" | "external-linked";
    evmV1Decoder: string | null;
    evmV1DecoderRuntimeCodeHash: string | null;
    decoderDeploymentTx: string | null;
    address: string;
    runtimeCodeHash: string;
    normalizedRuntimeCodeHash: string;
    deploymentTx: string | null;
  };
};

function deploymentPath(
  path = process.env.AGENTFIREWALL_LIVE_DEPLOYMENT_FILE?.trim() ||
    DEFAULT_LIVE_DEPLOYMENT_FILE
): string {
  return path;
}

function readArtifact(
  path: string
): LiveDeploymentArtifact {
  const parsed = JSON.parse(
    readFileSync(path, "utf8")
  ) as LiveDeploymentArtifact;

  if (parsed.version !== LIVE_DEPLOYMENT_ARTIFACT_VERSION) {
    throw new Error(
      `Unsupported live deployment artifact version in ${path}: ${String(parsed.version)}`
    );
  }

  if (parsed.source) {
    parsed.source.address = getAddress(parsed.source.address);
  }

  if (parsed.semanticRegistry) {
    parsed.semanticRegistry.address =
      getAddress(parsed.semanticRegistry.address);
    parsed.semanticRegistry.trustedAuthorizationSource =
      getAddress(parsed.semanticRegistry.trustedAuthorizationSource);

    if (parsed.semanticRegistry.evmV1Decoder) {
      parsed.semanticRegistry.evmV1Decoder =
        getAddress(parsed.semanticRegistry.evmV1Decoder);
    }
  }

  if (
    parsed.source &&
    parsed.semanticRegistry &&
    parsed.source.address !==
      parsed.semanticRegistry.trustedAuthorizationSource
  ) {
    throw new Error(
      `deployment source does not match registry source`
    );
  }

  return parsed;
}

export function loadLiveDeploymentArtifact(
  path = deploymentPath()
): LiveDeploymentArtifact | null {
  if (!existsSync(path)) {
    return null;
  }

  return readArtifact(path);
}

function writeArtifact(
  artifact: LiveDeploymentArtifact,
  path: string
): LiveDeploymentArtifact {
  mkdirSync(dirname(path), {
    recursive: true
  });

  writeFileSync(
    path,
    `${JSON.stringify(artifact, null, 2)}\n`,
    "utf8"
  );

  return artifact;
}

export function recordSourceDeployment(
  source: NonNullable<LiveDeploymentArtifact["source"]>,
  path = deploymentPath()
): LiveDeploymentArtifact {
  const artifact: LiveDeploymentArtifact = {
    version: LIVE_DEPLOYMENT_ARTIFACT_VERSION,
    updatedAt: new Date().toISOString(),
    source: {
      ...source,
      address: getAddress(source.address)
    }
  };

  return writeArtifact(
    artifact,
    path
  );
}

export function recordSemanticRegistryDeployment(
  semanticRegistry: NonNullable<LiveDeploymentArtifact["semanticRegistry"]>,
  path = deploymentPath()
): LiveDeploymentArtifact {
  const existing =
    loadLiveDeploymentArtifact(path);

  const trustedAuthorizationSource =
    getAddress(
      semanticRegistry.trustedAuthorizationSource
    );

  if (
    existing?.source &&
    existing.source.address !== trustedAuthorizationSource
  ) {
    throw new Error(
      `registry source does not match the recorded source`
    );
  }

  const artifact: LiveDeploymentArtifact = {
    version: LIVE_DEPLOYMENT_ARTIFACT_VERSION,
    updatedAt: new Date().toISOString(),
    source: existing?.source,
    semanticRegistry: {
      ...semanticRegistry,
      trustedAuthorizationSource,
      address:
        getAddress(semanticRegistry.address),
      evmV1Decoder:
        semanticRegistry.evmV1Decoder
          ? getAddress(semanticRegistry.evmV1Decoder)
          : null
    }
  };

  return writeArtifact(
    artifact,
    path
  );
}

export type ResolvedLiveDeploymentConfig = {
  sourceChainKey?: string;
  authorizationSource?: string;
  authorizationSourceRuntimeCodeHash?: string;
  registryAddress?: string;
  registryRuntimeCodeHash?: string;
};

function preferAndCrossCheck(
  label: string,
  configured: string | undefined,
  recorded: string | undefined,
  normalize: (value: string) => string = value => value
): string | undefined {
  if (configured && recorded) {
    const normalizedConfigured =
      normalize(configured);
    const normalizedRecorded =
      normalize(recorded);

    if (normalizedConfigured !== normalizedRecorded) {
      throw new Error(
        `${label}=${configured} conflicts with live deployment artifact value ${recorded}`
      );
    }

    return normalizedConfigured;
  }

  const selected =
    configured ?? recorded;

  return selected
    ? normalize(selected)
    : undefined;
}

export function resolveLiveDeploymentConfig(
  env: NodeJS.ProcessEnv = process.env,
  path = deploymentPath()
): ResolvedLiveDeploymentConfig {
  const artifact =
    loadLiveDeploymentArtifact(path);

  const recordedSource =
    artifact?.source?.address ??
    artifact?.semanticRegistry?.trustedAuthorizationSource;

  return {
    sourceChainKey:
      preferAndCrossCheck(
        "SOURCE_CHAIN_KEY",
        env.SOURCE_CHAIN_KEY?.trim(),
        artifact?.semanticRegistry?.sourceChainKey,
        value => BigInt(value).toString()
      ),
    authorizationSource:
      preferAndCrossCheck(
        "AUTHORIZATION_SOURCE_ADDRESS",
        env.AUTHORIZATION_SOURCE_ADDRESS?.trim(),
        recordedSource,
        value => getAddress(value)
      ),
    authorizationSourceRuntimeCodeHash:
      preferAndCrossCheck(
        "AUTHORIZATION_SOURCE_RUNTIME_CODE_HASH",
        env.AUTHORIZATION_SOURCE_RUNTIME_CODE_HASH?.trim(),
        artifact?.source?.runtimeCodeHash,
        value => value.toLowerCase()
      ),
    registryAddress:
      preferAndCrossCheck(
        "AGENTFIREWALL_REGISTRY_ADDRESS",
        env.AGENTFIREWALL_REGISTRY_ADDRESS?.trim(),
        artifact?.semanticRegistry?.address,
        value => getAddress(value)
      ),
    registryRuntimeCodeHash:
      preferAndCrossCheck(
        "AGENTFIREWALL_REGISTRY_RUNTIME_CODE_HASH",
        env.AGENTFIREWALL_REGISTRY_RUNTIME_CODE_HASH?.trim(),
        artifact?.semanticRegistry?.runtimeCodeHash,
        value => value.toLowerCase()
      )
  };
}
