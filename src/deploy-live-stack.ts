import {
  Contract,
  ContractFactory,
  JsonRpcProvider,
  Wallet,
  getAddress,
  keccak256
} from "ethers";

import {
  readFileSync,
  readdirSync
} from "node:fs";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  AUTHORIZATION_SOURCE_ABI
} from "./attestcoin-b2.js";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN,
  AUTHORIZATION_ID_DOMAIN,
  VERIFIED_AUTHORIZATION_REGISTRY_ABI,
  linkSolidityBytecode,
  maskSolidityByteRanges,
  validateSemanticRegistryTrustAnchors
} from "./semantic-registry.js";

import {
  DEFAULT_LIVE_DEPLOYMENT_FILE,
  recordSemanticRegistryDeployment,
  recordSourceDeployment,
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

import type {
  SolidityByteRanges,
  SolidityLinkReferences
} from "./semantic-registry.js";

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

function artifactFile(
  contractName: string,
  suffix: string
): string {
  const directory =
    "build/contracts";

  const file =
    readdirSync(directory).find(
      candidate =>
        candidate.endsWith(
          `_${contractName}.${suffix}`
        ) ||
        candidate ===
          `${contractName}.${suffix}`
    );

  if (!file) {
    throw new Error(
      `missing compiled ${suffix} artifact for ${contractName}`
    );
  }

  return `${directory}/${file}`;
}

function readRawBytecode(
  contractName: string
): string {
  const raw =
    readFileSync(
      artifactFile(
        contractName,
        "bin"
      ),
      "utf8"
    ).trim();

  if (!raw) {
    throw new Error(
      `Compiled bytecode for ${contractName} is empty`
    );
  }

  return raw;
}

function readBytecode(
  contractName: string
): string {
  const raw =
    readRawBytecode(contractName);

  if (!/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(
      `Compiled bytecode for ${contractName} still contains unresolved Solidity library links`
    );
  }

  return `0x${raw}`;
}

function readRuntimeBytecode(
  contractName: string
): string {
  const raw =
    readFileSync(
      artifactFile(
        contractName,
        "runtime.bin"
      ),
      "utf8"
    ).trim();

  if (!raw || !/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(
      `Compiled runtime bytecode for ${contractName} is missing or contains unresolved links`
    );
  }

  return `0x${raw}`;
}

function verifyExactRuntime(
  contractName: string,
  deployedCode: string
): string {
  const compiledRuntime =
    readRuntimeBytecode(contractName);

  const expectedHash =
    keccak256(compiledRuntime);
  const actualHash =
    keccak256(deployedCode);

  if (actualHash !== expectedHash) {
    throw new Error(
      `${contractName} runtime code hash mismatch: expected ${expectedHash}, got ${actualHash}`
    );
  }

  return actualHash;
}

function readLinkReferences(
  contractName: string
): SolidityLinkReferences {
  const raw =
    readFileSync(
      artifactFile(
        contractName,
        "links.json"
      ),
      "utf8"
    );

  return JSON.parse(raw) as SolidityLinkReferences;
}

function readRuntimeLinkReferences(
  contractName: string
): SolidityLinkReferences {
  const raw =
    readFileSync(
      artifactFile(
        contractName,
        "runtime.links.json"
      ),
      "utf8"
    );

  return JSON.parse(raw) as SolidityLinkReferences;
}

function readRuntimeImmutableReferences(
  contractName: string
): SolidityByteRanges {
  const raw =
    readFileSync(
      artifactFile(
        contractName,
        "runtime.immutables.json"
      ),
      "utf8"
    );

  return JSON.parse(raw) as SolidityByteRanges;
}

function countLinkReferences(
  references: SolidityLinkReferences
): number {
  return Object.values(references)
    .flatMap(sourceLibraries =>
      Object.values(sourceLibraries)
    )
    .reduce(
      (count, entries) =>
        count + entries.length,
      0
    );
}

function verifyRuntimeIgnoringImmutables(
  contractName: string,
  deployedCode: string,
  libraries: Record<string, string>
): {
  deployedRuntimeCodeHash: string;
  normalizedRuntimeCodeHash: string;
} {
  const rawRuntime =
    readFileSync(
      artifactFile(
        contractName,
        "runtime.bin"
      ),
      "utf8"
    ).trim();

  const linkedRuntime =
    linkSolidityBytecode(
      rawRuntime,
      readRuntimeLinkReferences(
        contractName
      ),
      libraries
    );

  const immutableRanges =
    readRuntimeImmutableReferences(
      contractName
    );

  const normalizedCompiled =
    maskSolidityByteRanges(
      linkedRuntime,
      immutableRanges
    );

  const normalizedDeployed =
    maskSolidityByteRanges(
      deployedCode,
      immutableRanges
    );

  if (
    normalizedCompiled.length !==
      normalizedDeployed.length ||
    keccak256(normalizedCompiled) !==
      keccak256(normalizedDeployed)
  ) {
    throw new Error(
      `${contractName} runtime differs from the local artifact`
    );
  }

  return {
    deployedRuntimeCodeHash:
      keccak256(deployedCode),
    normalizedRuntimeCodeHash:
      keccak256(normalizedDeployed)
  };
}

function uintEnv(
  name: string,
  bits?: number
): bigint {
  const raw = requiredEnv(name);

  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `${name} must be an unsigned integer`
    );
  }

  const value = BigInt(raw);

  if (
    bits !== undefined &&
    value >= (1n << BigInt(bits))
  ) {
    throw new Error(
      `${name} must fit uint${bits}`
    );
  }

  return value;
}

function testnetWallet(
  provider: JsonRpcProvider
): Wallet {
  return new Wallet(
    requiredEnv(
      "AGENTFIREWALL_TESTNET_PRIVATE_KEY"
    ),
    provider
  );
}

async function creditcoinProvider(): Promise<{
  provider: JsonRpcProvider;
  chainId: bigint;
}> {
  const network =
    resolveNetwork(
      "creditcoin-testnet"
    );

  const rpcUrl =
    trustedRpcForEnforcement(network).url;

  const provider =
    new JsonRpcProvider(rpcUrl);

  const detected =
    await provider.getNetwork();

  if (detected.chainId !== network.chainId) {
    throw new Error(
      `Refusing deployment: expected Creditcoin testnet ${network.chainId}, got ${detected.chainId}`
    );
  }

  return {
    provider,
    chainId: detected.chainId
  };
}

async function deploySource(): Promise<void> {
  const network =
    resolveNetwork("sepolia");

  const rpcUrl =
    trustedRpcForEnforcement(network).url;

  const provider =
    new JsonRpcProvider(rpcUrl);

  const detected =
    await provider.getNetwork();

  if (detected.chainId !== network.chainId) {
    throw new Error(
      `Refusing deployment: expected Sepolia ${network.chainId}, got ${detected.chainId}`
    );
  }

  const wallet =
    testnetWallet(provider);

  const factory =
    new ContractFactory(
      AUTHORIZATION_SOURCE_ABI,
      readBytecode(
        "AuthorizationSource"
      ),
      wallet
    );

  const contract =
    await factory.deploy();

  await contract.waitForDeployment();

  const sourceAddress =
    await contract.getAddress();

  const sourceCode =
    await provider.getCode(sourceAddress);

  if (sourceCode === "0x") {
    throw new Error(
      `AuthorizationSource deployment produced no runtime bytecode at ${sourceAddress}`
    );
  }

  const runtimeCodeHash =
    verifyExactRuntime(
      "AuthorizationSource",
      sourceCode
    );

  const deploymentTx =
    contract.deploymentTransaction()?.hash ?? null;

  recordSourceDeployment({
    network: "sepolia",
    chainId:
      detected.chainId.toString(),
    address:
      sourceAddress,
    runtimeCodeHash,
    deploymentTx
  });

  console.log(
    JSON.stringify(
      {
        contract:
          "AuthorizationSource",
        network:
          "Sepolia",
        chainId:
          detected.chainId.toString(),
        deployer:
          wallet.address,
        address:
          sourceAddress,
        runtimeCodeHash,
        deploymentTx,
        liveDeploymentArtifact:
          DEFAULT_LIVE_DEPLOYMENT_FILE
      },
      null,
      2
    )
  );
}

async function deploySemanticRegistry(): Promise<void> {
  const {
    provider,
    chainId
  } = await creditcoinProvider();

  const sourceChainKey =
    uintEnv(
      "SOURCE_CHAIN_KEY",
      64
    );

  const sourceChainId =
    uintEnv("SOURCE_CHAIN_ID");

  const sourceNetwork =
    resolveNetwork("sepolia");

  if (sourceChainId !== sourceNetwork.chainId) {
    throw new Error(
      `SOURCE_CHAIN_ID must be ${sourceNetwork.chainId}, got ${sourceChainId}`
    );
  }

  const deploymentConfig =
    resolveLiveDeploymentConfig();

  const authorizationSource =
    getAddress(
      deploymentConfig.authorizationSource ??
        requiredEnv(
          "AUTHORIZATION_SOURCE_ADDRESS"
        )
    );

  const sourceRpcUrl =
    trustedRpcForEnforcement(sourceNetwork).url;

  const sourceProvider =
    new JsonRpcProvider(sourceRpcUrl);

  const detectedSource =
    await sourceProvider.getNetwork();

  if (detectedSource.chainId !== sourceNetwork.chainId) {
    throw new Error(
      `expected Sepolia ${sourceNetwork.chainId}, got ${detectedSource.chainId}`
    );
  }

  const sourceCode =
    await sourceProvider.getCode(
      authorizationSource
    );

  if (sourceCode === "0x") {
    throw new Error(
      `AuthorizationSource ${authorizationSource} has no deployed bytecode on Sepolia`
    );
  }

  const sourceContract =
    new Contract(
      authorizationSource,
      AUTHORIZATION_SOURCE_ABI,
      sourceProvider
    );

  const [
    sourceCommitmentDomain,
    sourceIdDomain
  ] = await Promise.all([
    sourceContract.AUTHORIZATION_COMMITMENT_DOMAIN(),
    sourceContract.AUTHORIZATION_ID_DOMAIN()
  ]);

  if (
    String(sourceCommitmentDomain).toLowerCase() !==
      AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase() ||
    String(sourceIdDomain).toLowerCase() !==
      AUTHORIZATION_ID_DOMAIN.toLowerCase()
  ) {
    throw new Error(
      "AuthorizationSource domain constants mismatch"
    );
  }

  const wallet =
    testnetWallet(provider);

  const registryLinkReferences =
    readLinkReferences(
      "VerifiedAuthorizationRegistry"
    );

  const registryLinkCount =
    countLinkReferences(
      registryLinkReferences
    );

  let decoderAddress: string | null = null;
  let decoderRuntimeCodeHash: string | null = null;
  let decoderDeploymentTx: string | null = null;
  let registryLibraries: Record<string, string> = {};
  let linkedRegistryBytecode: string;

  if (registryLinkCount === 0) {
    linkedRegistryBytecode =
      readBytecode(
        "VerifiedAuthorizationRegistry"
      );
  } else {
    const decoderFactory =
      new ContractFactory(
        [],
        readBytecode(
          "EvmV1Decoder"
        ),
        wallet
      );

    const decoder =
      await decoderFactory.deploy();

    await decoder.waitForDeployment();

    const deployedDecoderAddress =
      await decoder.getAddress();

    decoderAddress =
      deployedDecoderAddress;

    decoderDeploymentTx =
      decoder.deploymentTransaction()?.hash ?? null;

    const decoderCode =
      await provider.getCode(
        deployedDecoderAddress
      );

    if (decoderCode === "0x") {
      throw new Error(
        `EvmV1Decoder deployment produced no runtime bytecode at ${deployedDecoderAddress}`
      );
    }

    decoderRuntimeCodeHash =
      verifyExactRuntime(
        "EvmV1Decoder",
        decoderCode
      );

    registryLibraries = {
      EvmV1Decoder:
        deployedDecoderAddress
    };

    linkedRegistryBytecode =
      linkSolidityBytecode(
        readRawBytecode(
          "VerifiedAuthorizationRegistry"
        ),
        registryLinkReferences,
        registryLibraries
      );
  }

  const registryFactory =
    new ContractFactory(
      VERIFIED_AUTHORIZATION_REGISTRY_ABI,
      linkedRegistryBytecode,
      wallet
    );

  const registry =
    await registryFactory.deploy(
      sourceChainKey,
      sourceChainId,
      authorizationSource
    );

  await registry.waitForDeployment();

  const registryAddress =
    await registry.getAddress();

  const registryCode =
    await provider.getCode(
      registryAddress
    );

  if (registryCode === "0x") {
    throw new Error(
      `VerifiedAuthorizationRegistry deployment produced no runtime bytecode at ${registryAddress}`
    );
  }

  const registryReader =
    new Contract(
      registryAddress,
      VERIFIED_AUTHORIZATION_REGISTRY_ABI,
      provider
    );

  const [
    deployedChainKey,
    deployedSourceChainId,
    deployedSource,
    deployedCommitmentDomain,
    deployedIdDomain
  ] = await Promise.all([
    registryReader.trustedSourceChainKey(),
    registryReader.trustedSourceChainId(),
    registryReader.trustedAuthorizationSource(),
    registryReader.AUTHORIZATION_COMMITMENT_DOMAIN(),
    registryReader.AUTHORIZATION_ID_DOMAIN()
  ]);

  validateSemanticRegistryTrustAnchors(
    {
      trustedSourceChainKey:
        deployedChainKey,
      trustedSourceChainId:
        deployedSourceChainId,
      trustedAuthorizationSource:
        String(deployedSource),
      authorizationCommitmentDomain:
        String(deployedCommitmentDomain),
      authorizationIdDomain:
        String(deployedIdDomain)
    },
    {
      sourceChainKey,
      sourceChainId,
      authorizationSource
    }
  );

  const registryRuntime =
    verifyRuntimeIgnoringImmutables(
      "VerifiedAuthorizationRegistry",
      registryCode,
      registryLibraries
    );

  const registryDeploymentTx =
    registry.deploymentTransaction()?.hash ?? null;

  recordSemanticRegistryDeployment({
    network: "creditcoin-testnet",
    chainId:
      chainId.toString(),
    sourceChainKey:
      sourceChainKey.toString(),
    sourceChainId:
      sourceChainId.toString(),
    trustedAuthorizationSource:
      authorizationSource,
    decoderMode:
      registryLinkCount === 0
        ? "inlined"
        : "external-linked",
    evmV1Decoder:
      decoderAddress,
    evmV1DecoderRuntimeCodeHash:
      decoderRuntimeCodeHash,
    decoderDeploymentTx,
    address:
      registryAddress,
    runtimeCodeHash:
      registryRuntime.deployedRuntimeCodeHash,
    normalizedRuntimeCodeHash:
      registryRuntime.normalizedRuntimeCodeHash,
    deploymentTx:
      registryDeploymentTx
  });

  console.log(
    JSON.stringify(
      {
        contract:
          "VerifiedAuthorizationRegistry",
        network:
          "Creditcoin CC3 Testnet",
        chainId:
          chainId.toString(),
        sourceChainKey:
          sourceChainKey.toString(),
        sourceChainId:
          sourceChainId.toString(),
        trustedAuthorizationSource:
          authorizationSource,
        decoderMode:
          registryLinkCount === 0
            ? "inlined"
            : "external-linked",
        evmV1Decoder:
          decoderAddress,
        evmV1DecoderRuntimeCodeHash:
          decoderRuntimeCodeHash,
        registry:
          registryAddress,
        registryRuntimeCodeHash:
          registryRuntime.deployedRuntimeCodeHash,
        registryNormalizedRuntimeCodeHash:
          registryRuntime.normalizedRuntimeCodeHash,
        deployer:
          wallet.address,
        decoderDeploymentTx,
        registryDeploymentTx,
        liveDeploymentArtifact:
          DEFAULT_LIVE_DEPLOYMENT_FILE
      },
      null,
      2
    )
  );
}

async function main(): Promise<void> {
  const target =
    requiredEnv("B2_DEPLOY_TARGET");

  if (target === "source") {
    await deploySource();
    return;
  }

  if (target === "semantic-registry") {
    await deploySemanticRegistry();
    return;
  }

  throw new Error(
    "B2_DEPLOY_TARGET must be source or semantic-registry"
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
