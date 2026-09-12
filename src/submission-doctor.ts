import {
  Contract,
  JsonRpcProvider,
  getAddress,
  keccak256
} from "ethers";

import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync
} from "node:fs";

import {
  resolveNetwork,
  rpcCandidates,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  sanitizeRpcError
} from "./rpc-security.js";

import {
  AUTHORIZATION_SOURCE_ABI
} from "./attestcoin-b2.js";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN,
  AUTHORIZATION_ID_DOMAIN,
  VERIFIED_AUTHORIZATION_REGISTRY_ABI,
  linkSolidityBytecode,
  maskSolidityByteRanges
} from "./semantic-registry.js";

import type {
  SolidityByteRanges,
  SolidityLinkReferences
} from "./semantic-registry.js";

import {
  loadLiveDeploymentArtifact,
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

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

const requiredFiles = [
  "README.md",
  "ARCHITECTURE.md",
  "THREAT_MODEL.md",
  "SUBMISSION.md",
  "DEMO_SCRIPT.md",
  "VALIDATION.md",
  "PROJECT_BASELINE.txt",
  "SECURITY.md",
  "contracts/AuthorizationSource.sol",
  "contracts/VerifiedAuthorizationRegistry.sol",
  "src/guarded-signer.ts",
  "src/controller-approval.ts",
  "src/sign-controller-approval.ts",
  "src/live-e2e.ts",
  "src/mcp-server.ts",
  "src/signer-observer.ts",
  "src/source-version.ts",
  "src/rpc-security.ts",
  "src/semantic-registry.ts",
  "src/attestcoin-semantic.ts",
  "src/live-demo.ts",
  "src/live-deployment.ts",
  "src/live-evidence.ts",
  "src/verify-live-evidence.ts",
  "src/verified-preflight.ts",
  "scripts/DEPLOY_B3_STACK.ps1",
  "scripts/RUN_BUIDL_LIVE_ROUNDTRIP.ps1",
  ".env.example"
] as const;

const expectedArtifacts = [
  "AuthorizationSource",
  "VerifiedAuthorizationRegistry",
  "EvmV1Decoder"
] as const;

function findArtifactFile(
  contractName: string,
  suffix: string
): string {
  const artifacts =
    readdirSync("build/contracts");

  const file =
    artifacts.find(candidate =>
      candidate === `${contractName}.${suffix}` ||
      candidate.endsWith(`_${contractName}.${suffix}`)
    );

  if (!file) {
    throw new Error(
      `compiled artifact ${contractName}.${suffix} is missing`
    );
  }

  return `build/contracts/${file}`;
}

function readArtifactText(
  contractName: string,
  suffix: string
): string {
  return readFileSync(
    findArtifactFile(
      contractName,
      suffix
    ),
    "utf8"
  ).trim();
}

function readArtifactJson<T>(
  contractName: string,
  suffix: string
): T {
  return JSON.parse(
    readArtifactText(
      contractName,
      suffix
    )
  ) as T;
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

function linkedLibraryAddressesFromRuntime(
  deployedCode: string,
  references: SolidityLinkReferences,
  libraryName: string
): string[] {
  const hex =
    deployedCode.startsWith("0x")
      ? deployedCode.slice(2)
      : deployedCode;

  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(
      "deployed runtime bytecode is not hexadecimal"
    );
  }

  const addresses =
    new Set<string>();

  for (const sourceLibraries of Object.values(references)) {
    const ranges =
      sourceLibraries[libraryName] ?? [];

    for (const range of ranges) {
      if (range.length !== 20) {
        throw new Error(
          `${libraryName} runtime link width is ${range.length}, expected 20`
        );
      }

      const start = range.start * 2;
      const end = start + 40;

      if (start < 0 || end > hex.length) {
        throw new Error(
          `${libraryName} runtime link reference is outside deployed bytecode`
        );
      }

      addresses.add(
        getAddress(`0x${hex.slice(start, end)}`)
      );
    }
  }

  return [...addresses];
}


function configuredRpcSecrets(): string[] {
  return [
    process.env.ETH_RPC_URL,
    process.env.SEPOLIA_RPC_URL,
    process.env.CREDITCOIN_RPC_URL
  ].filter((value): value is string => Boolean(value?.trim()));
}

function safeNetworkError(error: unknown): string {
  return sanitizeRpcError(
    error,
    configuredRpcSecrets()
  );
}

function fail(
  failures: string[],
  message: string
) {
  failures.push(message);
  console.error(`[FAIL] ${message}`);
}

function pass(message: string) {
  console.log(`[PASS] ${message}`);
}

function warn(message: string) {
  console.warn(`[WARN] ${message}`);
}

function parseHealthUrl(): string | null {
  const prefix = "--health-url=";
  const argument =
    process.argv.find(value => value.startsWith(prefix));

  return argument
    ? argument.slice(prefix.length)
    : null;
}

async function checkNetwork(
  chain: "ethereum" | "sepolia" | "creditcoin-testnet",
  failures: string[]
) {
  const network = resolveNetwork(chain);
  let endpoints: ReturnType<typeof rpcCandidates>;

  try {
    endpoints = chain === "ethereum"
      ? rpcCandidates(network)
      : [trustedRpcForEnforcement(network)];
  } catch (error) {
    fail(
      failures,
      `${network.name} trusted RPC configuration is unavailable: ${safeNetworkError(error)}`
    );
    return;
  }

  const endpointFailures: string[] = [];

  for (const endpoint of endpoints) {
    const provider = new JsonRpcProvider(
      endpoint.url,
      Number(network.chainId),
      { staticNetwork: true }
    );

    try {
      const chainIdRaw = await provider.send(
        "eth_chainId",
        []
      );
      const detectedChainId = BigInt(chainIdRaw);
      const blockNumber = await provider.getBlockNumber();

      if (detectedChainId !== network.chainId) {
        throw new Error(
          `chain mismatch: expected ${network.chainId}, got ${detectedChainId}`
        );
      }

      pass(
        `${network.name} RPC (${endpoint.source}) chain=${detectedChainId} block=${blockNumber}`
      );
      provider.destroy();
      return;
    } catch (error) {
      endpointFailures.push(
        `${endpoint.source}: ${safeNetworkError(error)}`
      );
      try {
        provider.destroy();
      } catch {}
    }
  }

  fail(
    failures,
    `${network.name} RPC unavailable: ${endpointFailures.join(" | ")}`
  );
}

async function workingProvider(
  chain: "sepolia" | "creditcoin-testnet"
): Promise<JsonRpcProvider> {
  const network =
    resolveNetwork(chain);
  const endpoint =
    trustedRpcForEnforcement(network);

  const provider =
    new JsonRpcProvider(
      endpoint.url,
      Number(network.chainId),
      { staticNetwork: true }
    );

  try {
    const chainId =
      BigInt(
        await provider.send(
          "eth_chainId",
          []
        )
      );

    if (chainId !== network.chainId) {
      throw new Error(
        `chain mismatch ${chainId}`
      );
    }

    return provider;
  } catch (error) {
    provider.destroy();
    throw new Error(
      `${network.name} trusted RPC ${endpoint.source} is unavailable: ${sanitizeRpcError(error, [endpoint.url])}`
    );
  }
}

async function checkSemanticTrustAnchors(
  failures: string[]
): Promise<boolean> {
  let deploymentConfig: ReturnType<typeof resolveLiveDeploymentConfig>;

  try {
    deploymentConfig =
      resolveLiveDeploymentConfig();
  } catch (error) {
    fail(
      failures,
      `live deployment artifact/config conflict: ${safeNetworkError(error)}`
    );
    return false;
  }

  const registryRaw =
    deploymentConfig.registryAddress;
  const sourceRaw =
    deploymentConfig.authorizationSource;
  const chainKeyRaw =
    deploymentConfig.sourceChainKey;

  if (!registryRaw && !sourceRaw && !chainKeyRaw) {
    warn(
      "semantic registry trust anchors not checked. Deploy B3 or set AGENTFIREWALL_REGISTRY_ADDRESS, AUTHORIZATION_SOURCE_ADDRESS and SOURCE_CHAIN_KEY."
    );
    return false;
  }

  if (!registryRaw || !sourceRaw || !chainKeyRaw) {
    fail(
      failures,
      "semantic trust-anchor validation requires AGENTFIREWALL_REGISTRY_ADDRESS, AUTHORIZATION_SOURCE_ADDRESS and SOURCE_CHAIN_KEY together"
    );
    return false;
  }

  if (!/^\d+$/.test(chainKeyRaw)) {
    fail(
      failures,
      "SOURCE_CHAIN_KEY must be an unsigned integer"
    );
    return false;
  }

  let registryAddress: string;
  let sourceAddress: string;

  try {
    registryAddress =
      getAddress(registryRaw);
    sourceAddress =
      getAddress(sourceRaw);
  } catch (error) {
    fail(
      failures,
      `semantic trust-anchor address is invalid: ${safeNetworkError(error)}`
    );
    return false;
  }

  let sourceProvider: JsonRpcProvider | null = null;
  let creditcoinProvider: JsonRpcProvider | null = null;
  let semanticRegistryLive = false;

  try {
    [sourceProvider, creditcoinProvider] =
      await Promise.all([
        workingProvider("sepolia"),
        workingProvider("creditcoin-testnet")
      ]);

    const [sourceCode, registryCode] =
      await Promise.all([
        sourceProvider.getCode(sourceAddress),
        creditcoinProvider.getCode(registryAddress)
      ]);

    if (sourceCode === "0x") {
      throw new Error(
        `no Sepolia bytecode at AuthorizationSource ${sourceAddress}`
      );
    }

    if (registryCode === "0x") {
      throw new Error(
        `no CC3 bytecode at VerifiedAuthorizationRegistry ${registryAddress}`
      );
    }

    const source =
      new Contract(
        sourceAddress,
        AUTHORIZATION_SOURCE_ABI,
        sourceProvider
      );

    const registry =
      new Contract(
        registryAddress,
        VERIFIED_AUTHORIZATION_REGISTRY_ABI,
        creditcoinProvider
      );

    const [
      sourceCommitmentDomain,
      sourceIdDomain,
      registryChainKey,
      registryChainId,
      registrySource,
      registryCommitmentDomain,
      registryIdDomain
    ] = await Promise.all([
      source.AUTHORIZATION_COMMITMENT_DOMAIN(),
      source.AUTHORIZATION_ID_DOMAIN(),
      registry.trustedSourceChainKey(),
      registry.trustedSourceChainId(),
      registry.trustedAuthorizationSource(),
      registry.AUTHORIZATION_COMMITMENT_DOMAIN(),
      registry.AUTHORIZATION_ID_DOMAIN()
    ]);

    const expectedSourceChainId =
      resolveNetwork("sepolia").chainId;

    if (
      String(sourceCommitmentDomain).toLowerCase() !==
      AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase() ||
      String(registryCommitmentDomain).toLowerCase() !==
      AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase()
    ) {
      throw new Error(
        "Authorization.v3 commitment domain mismatch between expected/source/registry"
      );
    }

    if (
      String(sourceIdDomain).toLowerCase() !==
      AUTHORIZATION_ID_DOMAIN.toLowerCase() ||
      String(registryIdDomain).toLowerCase() !==
      AUTHORIZATION_ID_DOMAIN.toLowerCase()
    ) {
      throw new Error(
        "AuthorizationId.v1 domain mismatch between expected/source/registry"
      );
    }

    if (BigInt(registryChainKey) !== BigInt(chainKeyRaw)) {
      throw new Error(
        `registry chainKey ${registryChainKey} != configured ${chainKeyRaw}`
      );
    }

    if (BigInt(registryChainId) !== expectedSourceChainId) {
      throw new Error(
        `registry source chainId ${registryChainId} != Sepolia ${expectedSourceChainId}`
      );
    }

    if (getAddress(registrySource) !== sourceAddress) {
      throw new Error(
        `registry trusted source ${registrySource} != configured ${sourceAddress}`
      );
    }

    const compiledSourceRuntime =
      `0x${readArtifactText(
        "AuthorizationSource",
        "runtime.bin"
      )}`;

    if (
      keccak256(sourceCode) !==
      keccak256(compiledSourceRuntime)
    ) {
      throw new Error(
        "deployed AuthorizationSource runtime does not match the locally compiled source artifact"
      );
    }

    const registryRuntimeLinks =
      readArtifactJson<SolidityLinkReferences>(
        "VerifiedAuthorizationRegistry",
        "runtime.links.json"
      );

    const runtimeLinkCount =
      countLinkReferences(
        registryRuntimeLinks
      );

    let registryLibraries: Record<string, string> = {};
    let decoderSummary = "inlined";

    if (runtimeLinkCount === 0) {
      pass(
        "semantic registry uses the pinned inlined EvmV1Decoder path (no runtime library link slots)"
      );
    } else {
      const decoderAddresses =
        linkedLibraryAddressesFromRuntime(
          registryCode,
          registryRuntimeLinks,
          "EvmV1Decoder"
        );

      if (decoderAddresses.length !== 1) {
        throw new Error(
          `expected one EvmV1Decoder link, got ${decoderAddresses.length}`
        );
      }

      const decoderAddress =
        decoderAddresses[0];

      const decoderCode =
        await creditcoinProvider.getCode(
          decoderAddress
        );

      if (decoderCode === "0x") {
        throw new Error(
          `linked EvmV1Decoder ${decoderAddress} has no Creditcoin bytecode`
        );
      }

      const compiledDecoderRuntime =
        `0x${readArtifactText(
          "EvmV1Decoder",
          "runtime.bin"
        )}`;

      if (
        keccak256(decoderCode) !==
        keccak256(compiledDecoderRuntime)
      ) {
        throw new Error(
          "linked EvmV1Decoder runtime does not match the locally compiled @gluwa/asc-contracts artifact"
        );
      }

      registryLibraries = {
        EvmV1Decoder:
          decoderAddress
      };
      decoderSummary = decoderAddress;
    }

    const compiledRegistryRuntime =
      linkSolidityBytecode(
        readArtifactText(
          "VerifiedAuthorizationRegistry",
          "runtime.bin"
        ),
        registryRuntimeLinks,
        registryLibraries
      );

    const immutableRanges =
      readArtifactJson<SolidityByteRanges>(
        "VerifiedAuthorizationRegistry",
        "runtime.immutables.json"
      );

    const normalizedCompiledRegistry =
      maskSolidityByteRanges(
        compiledRegistryRuntime,
        immutableRanges
      );

    const normalizedDeployedRegistry =
      maskSolidityByteRanges(
        registryCode,
        immutableRanges
      );

    if (
      normalizedCompiledRegistry.length !==
        normalizedDeployedRegistry.length ||
      keccak256(normalizedCompiledRegistry) !==
        keccak256(normalizedDeployedRegistry)
    ) {
      throw new Error(
        "deployed registry runtime differs from the local artifact"
      );
    }

    pass(
      `semantic trust anchors + deployed bytecode verified: source=${sourceAddress} registry=${registryAddress} decoder=${decoderSummary} chainKey=${chainKeyRaw}`
    );

    try {
      const artifactPath =
        process.env.AGENTFIREWALL_LIVE_AUTH_FILE?.trim() ||
        DEFAULT_LIVE_DEMO_FILE;
      const evidencePath =
        process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
        DEFAULT_LIVE_EVIDENCE_FILE;

      if (existsSync(artifactPath) && existsSync(evidencePath)) {
        const artifact = JSON.parse(
          readFileSync(artifactPath, "utf8")
        ) as LiveAuthorizationArtifact;
        const evidence = JSON.parse(
          readFileSync(evidencePath, "utf8")
        ) as LiveJudgeEvidence;

        if (artifact.version !== LIVE_DEMO_ARTIFACT_VERSION) {
          throw new Error("unsupported live authorization artifact version");
        }

        const record = await registry.getAuthorization(
          artifact.source.authorizationId
        );

        semanticRegistryLive =
          historicalEvidenceMatchesArtifacts({
            deployment: loadLiveDeploymentArtifact(),
            artifact,
            evidence,
            registryRecord: {
              commitment: String(record.commitment),
              sourceChainKey: BigInt(record.sourceChainKey).toString(),
              sourceBlockNumber: BigInt(record.sourceBlockNumber).toString(),
              transactionIndex: BigInt(record.transactionIndex).toString(),
              validUntil: BigInt(record.validUntil).toString(),
              verified: Boolean(record.verified)
            }
          });
      }
    } catch {
      semanticRegistryLive = false;
    }
  } catch (error) {
    fail(
      failures,
      `semantic trust-anchor validation failed: ${safeNetworkError(error)}`
    );
  } finally {
    sourceProvider?.destroy();
    creditcoinProvider?.destroy();
  }

  return semanticRegistryLive;
}

async function checkHealth(
  healthUrl: string,
  failures: string[],
  historicalSemanticRegistryVerified: boolean
) {
  try {
    const response = await fetch(healthUrl);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const body = await response.json() as Record<string, unknown>;

    const requiredTrue = [
      "standardPreflight",
      "intentIntegrity",
      "verifiedPreflightEndpoint",
      "controllerApprovalRequiredByGuardedSigner",
      "mcpAgentAdapter",
      "feePolicyRequiredByGuardedSigner",
      "verifiedEnforcementRequiresExplicitRpc",
      "replayBoundExecutionNonce",
      "authorizationExpiryUsesChainTime",
      "executionPayloadCommitment",
      "targetRuntimeCodeHashBinding",
      "semanticAuthorizationRegistryImplemented",
      "historicalLiveEvidenceArtifactConsistent"
    ];

    for (const field of requiredTrue) {
      if (body[field] !== true) {
        throw new Error(
          `health field ${field} is not true`
        );
      }
    }

    if (body.build !== "1.0.0-rc.6-agent-demo") {
      throw new Error(
        `unexpected build: ${String(body.build)}`
      );
    }

    if (body.strongSigningBoundary !== "GuardedSigner signer boundary") {
      throw new Error(
        `unexpected signing boundary: ${String(body.strongSigningBoundary)}`
      );
    }

    if (body.upgradeableProxyPolicy !== "detected-common-proxies-fail-closed") {
      throw new Error(
        `unexpected proxy policy: ${String(body.upgradeableProxyPolicy)}`
      );
    }

    if (
      body.historicalSemanticRegistryVerified !==
      historicalSemanticRegistryVerified
    ) {
      throw new Error(
        `health registry state differs from doctor result`
      );
    }

    if (typeof body.authorizationChainWindowOpen !== "boolean") {
      throw new Error(
        "health authorizationChainWindowOpen must be boolean"
      );
    }

    if (body.authorizationCurrentlyUsable !== false) {
      throw new Error(
        "health must not report a generic current ALLOW"
      );
    }

    if (
      typeof body.currentAuthorizationEvaluation !== "string" ||
      !body.currentAuthorizationEvaluation.startsWith("not-evaluated:")
    ) {
      throw new Error(
        "health currentAuthorizationEvaluation is invalid"
      );
    }

    pass(`health endpoint ${healthUrl}`);

    if (historicalSemanticRegistryVerified) {
      pass(
        "historical Creditcoin semantic-registry evidence validated"
      );
    } else {
      warn(
        "historical semantic-registry state could not be re-verified with the currently configured RPC; this does not convert the historical artifact into a current authorization."
      );
    }

    if (body.authorizationCurrentlyUsable === false) {
      pass(
        "health does not present the historical authorization as a generic current ALLOW capability"
      );
    }

    if (body.authorizationChainWindowOpen === false) {
      pass(
        "health reports the historical authorization chain window as closed"
      );
    }
  } catch (error) {
    fail(
      failures,
      `health endpoint failed: ${safeNetworkError(error)}`
    );
  }
}

async function main() {
  const failures: string[] = [];

  console.log(
    "AgentFirewall submission doctor — 1.0.0-rc.6 agent demo"
  );

  for (const file of requiredFiles) {
    if (!existsSync(file)) {
      fail(failures, `required file missing: ${file}`);
      continue;
    }

    if (statSync(file).size === 0) {
      fail(failures, `required file is empty: ${file}`);
      continue;
    }

    pass(`required file ${file}`);
  }

  try {
    const packageJson = JSON.parse(
      readFileSync("package.json", "utf8")
    ) as {
      version?: string;
      scripts?: Record<string, string>;
    };

    if (packageJson.version !== "1.0.0-rc.6") {
      fail(
        failures,
        `package version must be 1.0.0-rc.6, got ${String(packageJson.version)}`
      );
    } else {
      pass("package version 1.0.0-rc.6");
    }

    for (const script of [
      "typecheck",
      "test",
      "contracts:compile",
      "b3:deploy",
      "demo:submission",
      "submission:doctor",
      "attestcoin:ingest-authorization",
      "attestcoin:publish-demo-authorization",
      "demo:verified-live",
      "controller:approve-live",
      "live:e2e",
      "mcp",
      "live:evidence",
      "live:evidence:local"
    ]) {
      if (!packageJson.scripts?.[script]) {
        fail(failures, `npm script missing: ${script}`);
      } else {
        pass(`npm script ${script}`);
      }
    }
  } catch (error) {
    fail(
      failures,
      `package.json cannot be validated: ${safeNetworkError(error)}`
    );
  }

  if (!existsSync("build/contracts")) {
    fail(
      failures,
      "build/contracts is missing; run npm run contracts:compile"
    );
  } else {
    const artifacts = readdirSync("build/contracts");

    for (const contractName of expectedArtifacts) {
      for (const extension of [
        "abi",
        "bin",
        "runtime.bin",
        "runtime.links.json",
        "runtime.immutables.json"
      ] as const) {
        const found = artifacts.find(
          file =>
            file === `${contractName}.${extension}` ||
            file.endsWith(`_${contractName}.${extension}`)
        );

        if (!found) {
          fail(
            failures,
            `compiled ${extension.toUpperCase()} missing for ${contractName}`
          );
          continue;
        }

        if (statSync(`build/contracts/${found}`).size === 0) {
          fail(
            failures,
            `compiled artifact is empty: ${found}`
          );
          continue;
        }

        pass(`compiled artifact ${found}`);
      }
    }

    const registryLinksFile =
      artifacts.find(
        file =>
          file === "VerifiedAuthorizationRegistry.links.json" ||
          file.endsWith("_VerifiedAuthorizationRegistry.links.json")
      );

    if (!registryLinksFile) {
      fail(
        failures,
        "compiler link-reference artifact missing for VerifiedAuthorizationRegistry"
      );
    } else {
      try {
        const links =
          JSON.parse(
            readFileSync(
              `build/contracts/${registryLinksFile}`,
              "utf8"
            )
          ) as Record<
            string,
            Record<string, unknown[]>
          >;

        const linkCount =
          Object.values(links)
            .flatMap(libraries =>
              Object.values(libraries)
            )
            .reduce(
              (count, references) =>
                count + references.length,
              0
            );

        if (linkCount === 0) {
          pass(
            "semantic registry compile path: EvmV1Decoder inlined by solc; external library linking not required"
          );
        } else {
          pass(
            `semantic registry external-library link references=${linkCount}`
          );
        }
      } catch (error) {
        fail(
          failures,
          `cannot validate ${registryLinksFile}: ${safeNetworkError(error)}`
        );
      }
    }

    try {
      const runtimeLinks =
        readArtifactJson<SolidityLinkReferences>(
          "VerifiedAuthorizationRegistry",
          "runtime.links.json"
        );

      const runtimeLinkCount =
        Object.values(runtimeLinks)
          .flatMap(libraries =>
            Object.values(libraries)
          )
          .reduce(
            (count, references) =>
              count + references.length,
            0
          );

      if (runtimeLinkCount === 0) {
        pass(
          "semantic registry runtime: EvmV1Decoder is inlined; no runtime link reference required"
        );
      } else {
        pass(
          `semantic registry runtime link references=${runtimeLinkCount}`
        );
      }
    } catch (error) {
      fail(
        failures,
        `cannot validate semantic registry runtime link references: ${safeNetworkError(error)}`
      );
    }
  }

  await checkNetwork("ethereum", failures);
  await checkNetwork("sepolia", failures);
  await checkNetwork("creditcoin-testnet", failures);
  const semanticRegistryLive =
    await checkSemanticTrustAnchors(failures);

  const healthUrl = parseHealthUrl();

  if (healthUrl) {
    await checkHealth(
      healthUrl,
      failures,
      semanticRegistryLive
    );
  } else {
    warn(
      "health endpoint not checked. Optional: npm run submission:doctor -- --health-url=http://127.0.0.1:8787/api/health"
    );
  }

  if (failures.length > 0) {
    console.error(
      `\nSUBMISSION DOCTOR FAILED: ${failures.length} issue(s).`
    );
    process.exitCode = 1;
    return;
  }

  console.log(
    "\nSUBMISSION DOCTOR PASSED: release structure, deployment/runtime contract artifacts, trust anchors and all three network RPCs are ready."
  );
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
