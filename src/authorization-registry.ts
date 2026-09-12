import {
  Interface,
  JsonRpcProvider,
  getAddress,
  id,
  isHexString,
  keccak256,
  toBeHex
} from "ethers";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN
} from "./authorization.js";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

import {
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

import {
  redactRpcEndpoint,
  sanitizeRpcError
} from "./rpc-security.js";

import {
  normalizeAuthorizationId,
  normalizeCommitment,
  type VerifiedAuthorizationReader,
  type VerifiedAuthorizationRecord
} from "./verified-authorization.js";

const AUTHORIZATION_ID_DOMAIN =
  id("AgentFirewall.AuthorizationId.v1");

const REGISTRY_ABI = [
  "function getAuthorization(bytes32 authorizationId) view returns (bytes32 commitment,uint64 sourceChainKey,uint64 sourceBlockNumber,uint64 transactionIndex,uint64 validUntil,bool verified)",
  "function trustedSourceChainKey() view returns (uint64)",
  "function trustedSourceChainId() view returns (uint256)",
  "function trustedAuthorizationSource() view returns (address)",
  "function AUTHORIZATION_COMMITMENT_DOMAIN() view returns (bytes32)",
  "function AUTHORIZATION_ID_DOMAIN() view returns (bytes32)"
];

export type SemanticRegistryTrustConfig = {
  sourceChainKey: string;
  sourceChainId: string;
  authorizationSource: string;
};

export function normalizeSemanticRegistryTrustConfig(
  sourceChainKey: string | undefined,
  authorizationSource: string | undefined
): SemanticRegistryTrustConfig {
  if (!sourceChainKey || !/^(0|[1-9][0-9]*)$/.test(sourceChainKey)) {
    throw new Error(
      "SOURCE_CHAIN_KEY must be a non-zero uint64"
    );
  }

  const parsedChainKey =
    BigInt(sourceChainKey);

  if (
    parsedChainKey === 0n ||
    parsedChainKey > (1n << 64n) - 1n
  ) {
    throw new Error(
      "SOURCE_CHAIN_KEY must be greater than zero and fit uint64"
    );
  }

  if (!authorizationSource) {
    throw new Error(
      "AUTHORIZATION_SOURCE_ADDRESS must be configured for semantic verified-authorization mode"
    );
  }

  return {
    sourceChainKey:
      parsedChainKey.toString(),
    sourceChainId:
      resolveNetwork("sepolia").chainId.toString(),
    authorizationSource:
      getAddress(authorizationSource)
  };
}

export class CreditcoinAuthorizationRegistryReader
implements VerifiedAuthorizationReader {
  private readonly provider: JsonRpcProvider;
  private readonly registryAddress: string;
  private readonly rpcUrl: string;
  private readonly rpcSourceLabel: string;
  private readonly trustConfig: SemanticRegistryTrustConfig;
  private readonly expectedRuntimeCodeHash: string;
  private readonly registryInterface =
    new Interface(REGISTRY_ABI);

  constructor(
    registryAddress: string,
    trustConfig: SemanticRegistryTrustConfig,
    rpcUrl: string,
    expectedRuntimeCodeHash: string,
    rpcSourceLabel = "creditcoin-trusted-config"
  ) {
    this.registryAddress =
      getAddress(registryAddress);

    if (!isHexString(expectedRuntimeCodeHash, 32)) {
      throw new Error(
        "Expected VerifiedAuthorizationRegistry runtime code hash must be exactly 32 bytes"
      );
    }

    this.expectedRuntimeCodeHash =
      expectedRuntimeCodeHash.toLowerCase();
    this.rpcUrl = rpcUrl;
    this.rpcSourceLabel = rpcSourceLabel;
    this.trustConfig = trustConfig;

    // Registry reads trust one configured RPC.
    this.provider =
      new JsonRpcProvider(
        rpcUrl,
        Number(resolveNetwork("creditcoin-testnet").chainId),
        { staticNetwork: true }
      );
  }

  private async rawCall(
    functionName: string,
    args: readonly unknown[],
    blockTag: string
  ): Promise<readonly unknown[]> {
    const data =
      this.registryInterface.encodeFunctionData(
        functionName,
        args
      );

    const result = await this.provider.send(
      "eth_call",
      [
        {
          to: this.registryAddress,
          data
        },
        blockTag
      ]
    );

    if (typeof result !== "string") {
      throw new Error(
        `Registry ${functionName} eth_call returned a non-string result`
      );
    }

    return this.registryInterface.decodeFunctionResult(
      functionName,
      result
    );
  }

  private async readAuthorization(
    authorizationId: string
  ): Promise<VerifiedAuthorizationRecord | null> {
    const normalizedId =
      normalizeAuthorizationId(
        authorizationId
      );

    const network =
      await this.provider.getNetwork();

    const expectedChainId =
      resolveNetwork(
        "creditcoin-testnet"
      ).chainId;

    if (network.chainId !== expectedChainId) {
      throw new Error(
        `Creditcoin registry RPC chain mismatch: expected ${expectedChainId}, got ${network.chainId}`
      );
    }

    const block =
      await this.provider.getBlock("latest");

    if (!block || !block.hash) {
      throw new Error(
        "Unable to obtain a complete Creditcoin registry snapshot block"
      );
    }

    const blockTag =
      toBeHex(block.number);

    const code = await this.provider.send(
      "eth_getCode",
      [this.registryAddress, blockTag]
    );

    if (typeof code !== "string" || code === "0x") {
      throw new Error(
        `No contract bytecode at configured registry ${this.registryAddress}`
      );
    }

    const actualRuntimeCodeHash =
      keccak256(code).toLowerCase();

    if (
      actualRuntimeCodeHash !==
      this.expectedRuntimeCodeHash
    ) {
      throw new Error(
        `registry code hash mismatch: expected ${this.expectedRuntimeCodeHash}, got ${actualRuntimeCodeHash}`
      );
    }

    const [
      trustedSourceChainKeyResult,
      trustedSourceChainIdResult,
      trustedAuthorizationSourceResult,
      registryCommitmentDomainResult,
      registryAuthorizationIdDomainResult,
      authorizationResult
    ] = await Promise.all([
      this.rawCall(
        "trustedSourceChainKey",
        [],
        blockTag
      ),
      this.rawCall(
        "trustedSourceChainId",
        [],
        blockTag
      ),
      this.rawCall(
        "trustedAuthorizationSource",
        [],
        blockTag
      ),
      this.rawCall(
        "AUTHORIZATION_COMMITMENT_DOMAIN",
        [],
        blockTag
      ),
      this.rawCall(
        "AUTHORIZATION_ID_DOMAIN",
        [],
        blockTag
      ),
      this.rawCall(
        "getAuthorization",
        [normalizedId],
        blockTag
      )
    ]);

    const confirmedBlock =
      await this.provider.getBlock(block.number);

    if (
      !confirmedBlock?.hash ||
      confirmedBlock.hash.toLowerCase() !==
        block.hash.toLowerCase()
    ) {
      throw new Error(
        `Creditcoin registry snapshot changed during verification at block ${block.number}`
      );
    }

    const trustedSourceChainKey =
      BigInt(trustedSourceChainKeyResult[0] as bigint);
    const trustedSourceChainId =
      BigInt(trustedSourceChainIdResult[0] as bigint);
    const trustedAuthorizationSource =
      String(trustedAuthorizationSourceResult[0]);
    const registryCommitmentDomain =
      String(registryCommitmentDomainResult[0]);
    const registryAuthorizationIdDomain =
      String(registryAuthorizationIdDomainResult[0]);

    if (
      trustedSourceChainKey.toString() !==
      this.trustConfig.sourceChainKey
    ) {
      throw new Error(
        `registry chain key mismatch: ${trustedSourceChainKey}`
      );
    }

    if (
      trustedSourceChainId.toString() !==
      this.trustConfig.sourceChainId
    ) {
      throw new Error(
        `registry chain id mismatch: ${trustedSourceChainId}`
      );
    }

    if (
      getAddress(trustedAuthorizationSource) !==
      this.trustConfig.authorizationSource
    ) {
      throw new Error(
        `registry source mismatch: ${trustedAuthorizationSource}`
      );
    }

    if (
      registryCommitmentDomain.toLowerCase() !==
      AUTHORIZATION_COMMITMENT_DOMAIN.toLowerCase()
    ) {
      throw new Error(
        `registry commitment domain mismatch: ${registryCommitmentDomain}`
      );
    }

    if (
      registryAuthorizationIdDomain.toLowerCase() !==
      AUTHORIZATION_ID_DOMAIN.toLowerCase()
    ) {
      throw new Error(
        `registry authorization-id domain mismatch: ${registryAuthorizationIdDomain}`
      );
    }

    const commitment =
      String(authorizationResult[0]);
    const sourceChainKey =
      BigInt(authorizationResult[1] as bigint);
    const sourceBlockNumber =
      BigInt(authorizationResult[2] as bigint);
    const transactionIndex =
      BigInt(authorizationResult[3] as bigint);
    const validUntil =
      BigInt(authorizationResult[4] as bigint);
    const verified =
      Boolean(authorizationResult[5]);

    if (
      !verified &&
      commitment ===
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    ) {
      return null;
    }

    return {
      authorizationId:
        normalizedId,
      commitment:
        normalizeCommitment(
          commitment,
          "registry commitment"
        ),
      verified,
      sourceChainKey:
        sourceChainKey.toString(),
      sourceBlockNumber:
        sourceBlockNumber.toString(),
      transactionIndex:
        transactionIndex.toString(),
      validUntil:
        validUntil.toString(),
      registryAddress:
        this.registryAddress,
      creditcoinChainId:
        network.chainId.toString(),
      rpcSource:
        this.rpcSourceLabel,
      registryTrustAnchorsVerified: true,
      registryRuntimeCodeHashVerified: true,
      registrySnapshotBlockNumber:
        block.number.toString(),
      registrySnapshotBlockHash:
        block.hash
    };
  }

  async getAuthorization(
    authorizationId: string
  ): Promise<VerifiedAuthorizationRecord | null> {
    try {
      return await this.readAuthorization(
        authorizationId
      );
    } catch (error) {
      throw new Error(
        sanitizeRpcError(
          error,
          [this.rpcUrl]
        )
      );
    }
  }
}

export function createConfiguredAuthorizationReader():
  VerifiedAuthorizationReader {
  let deploymentConfig: ReturnType<typeof resolveLiveDeploymentConfig>;

  try {
    deploymentConfig =
      resolveLiveDeploymentConfig();
  } catch (error) {
    return {
      async getAuthorization() {
        throw error;
      }
    };
  }

  const registryAddress =
    deploymentConfig.registryAddress;
  const registryRuntimeCodeHash =
    deploymentConfig.registryRuntimeCodeHash;

  if (!registryAddress) {
    return {
      async getAuthorization() {
        throw new Error(
          "AGENTFIREWALL_REGISTRY_ADDRESS is not configured"
        );
      }
    };
  }

  if (!registryRuntimeCodeHash) {
    return {
      async getAuthorization() {
        throw new Error(
          "Verified enforcement requires an expected VerifiedAuthorizationRegistry runtime code hash"
        );
      }
    };
  }

  let trustConfig: SemanticRegistryTrustConfig;

  try {
    trustConfig =
      normalizeSemanticRegistryTrustConfig(
        deploymentConfig.sourceChainKey,
        deploymentConfig.authorizationSource
      );
  } catch (error) {
    return {
      async getAuthorization() {
        throw error;
      }
    };
  }

  try {
    const endpoint =
      trustedRpcForEnforcement(
        resolveNetwork("creditcoin-testnet")
      );

    return new CreditcoinAuthorizationRegistryReader(
      registryAddress,
      trustConfig,
      endpoint.url,
      registryRuntimeCodeHash,
      `${endpoint.source}@${redactRpcEndpoint(endpoint.url)}`
    );
  } catch (error) {
    return {
      async getAuthorization() {
        throw error;
      }
    };
  }
}
