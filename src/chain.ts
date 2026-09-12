import {
  JsonRpcProvider,
  ZeroAddress,
  getAddress,
  isAddress,
  keccak256,
  toBeHex,
  toQuantity,
  type Provider
} from "ethers";

import {
  resolveNetwork,
  rpcCandidates,
  trustedRpcForEnforcement,
  type NetworkConfig
} from "./networks.js";

import {
  redactRpcEndpoint,
  sanitizeRpcError
} from "./rpc-security.js";

export type ChainTransaction = {
  chain?: string;
  from?: string;
  to: string;
  data?: string;
  valueWei?: string;
  nonce?: string;
};

export type ProxyIdentity = {
  assessment: "not-detected" | "detected" | "unknown";
  kind: "none" | "eip1967" | "eip1967-beacon" | "eip1167" | "unknown";
  implementation?: string;
  implementationCodeHash?: string;
  beacon?: string;
  reason?: string;
};

export type ChainInspection = {
  network: {
    key: string;
    name: string;
    chainId: string;
    blockNumber: number;
    blockHash: string;
    timestamp: number;
  };
  destination: {
    address: string;
    kind: string;
    balanceWei: string;
    bytecodeBytes: number;
    codeHash: string;
    proxy: ProxyIdentity;
  };
  transaction: {
    from?: string;
    to: string;
    valueWei: string;
    calldataBytes: number;
  };
  simulation:
    | { ok: true; result: string }
    | { ok: false; error: string };
  gasEstimate:
    | { ok: true; gas: string; advisory: true }
    | { ok: false; error: string; advisory: true };
  rpcSource: string;
};

type WorkingProvider = {
  provider: JsonRpcProvider;
  url: string;
  source: string;
};

type RpcSendProvider = Provider & {
  send(method: string, params: Array<unknown>): Promise<unknown>;
};

const providerCache =
  new Map<string, WorkingProvider>();

const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_BEACON_SLOT =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

function parseValue(
  value: string | undefined
): bigint {
  const raw = value ?? "0";

  if (!/^\d+$/.test(raw)) {
    throw new Error(
      "valueWei must be an unsigned integer"
    );
  }

  return BigInt(raw);
}

function validateData(data: string): void {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    throw new Error(
      "Calldata must be hexadecimal bytes beginning with 0x"
    );
  }
}

function errorMessage(
  error: unknown,
  rpcUrl?: string
): string {
  return sanitizeRpcError(
    error,
    rpcUrl ? [rpcUrl] : []
  );
}

function hasRpcSend(
  provider: Provider
): provider is RpcSendProvider {
  return typeof (provider as Partial<RpcSendProvider>).send === "function";
}

async function verifyProviderIdentity(
  provider: JsonRpcProvider,
  network: NetworkConfig
): Promise<void> {
  const chainIdRaw =
    await provider.send(
      "eth_chainId",
      []
    );

  const chainId = BigInt(chainIdRaw);

  if (chainId !== network.chainId) {
    throw new Error(
      `Expected chain ${network.chainId.toString()}, received ${chainId.toString()}`
    );
  }
}

function destroyProvider(
  active: WorkingProvider
): void {
  try {
    active.provider.destroy();
  } catch {}
}

function invalidateProvider(
  network: NetworkConfig,
  active: WorkingProvider
): void {
  const cached = providerCache.get(network.key);

  if (cached?.url === active.url) {
    providerCache.delete(network.key);
  }

  destroyProvider(active);
}

async function findWorkingProvider(
  network: NetworkConfig,
  excludedUrls: ReadonlySet<string> = new Set()
): Promise<WorkingProvider> {
  const cached = providerCache.get(network.key);

  if (
    cached &&
    !excludedUrls.has(cached.url)
  ) {
    try {
      await verifyProviderIdentity(
        cached.provider,
        network
      );

      return cached;
    } catch (error) {
      console.warn(
        `[RPC] cached ${network.key} provider failed: ${errorMessage(error, cached.url)}`
      );

      invalidateProvider(
        network,
        cached
      );
    }
  }

  const failures: string[] = [];

  for (const endpoint of rpcCandidates(network)) {
    if (excludedUrls.has(endpoint.url)) {
      continue;
    }

    const provider = new JsonRpcProvider(
      endpoint.url,
      Number(network.chainId),
      { staticNetwork: true }
    );

    const active = {
      provider,
      url: endpoint.url,
      source: endpoint.source
    };

    try {
      await verifyProviderIdentity(
        provider,
        network
      );

      providerCache.set(
        network.key,
        active
      );

      console.log(
        `[RPC] Using ${network.key}/${endpoint.source}: ${redactRpcEndpoint(endpoint.url)}`
      );

      return active;
    } catch (error) {
      const message = errorMessage(
        error,
        endpoint.url
      );

      failures.push(
        `${endpoint.source}: ${message}`
      );

      console.warn(
        `[RPC] ${network.key}/${endpoint.source} failed: ${message}`
      );

      destroyProvider(active);
    }
  }

  throw new Error(
    `No RPC endpoint for ${network.name} is currently available:\n` +
    failures.join("\n")
  );
}

function storageAddress(
  slot: string
): string | null {
  if (!/^0x[0-9a-fA-F]{64}$/.test(slot)) {
    return null;
  }

  const raw = `0x${slot.slice(-40)}`;

  if (raw.toLowerCase() === ZeroAddress.toLowerCase()) {
    return null;
  }

  try {
    return getAddress(raw);
  } catch {
    return null;
  }
}

async function rawGetCode(
  rpc: RpcSendProvider,
  address: string,
  blockTag: string
): Promise<string> {
  const value = await rpc.send(
    "eth_getCode",
    [address, blockTag]
  );

  if (typeof value !== "string") {
    throw new Error("eth_getCode returned a non-string result");
  }

  return value;
}

async function rawGetBalance(
  rpc: RpcSendProvider,
  address: string,
  blockTag: string
): Promise<bigint> {
  const value = await rpc.send(
    "eth_getBalance",
    [address, blockTag]
  );

  if (typeof value !== "string") {
    throw new Error("eth_getBalance returned a non-string result");
  }

  return BigInt(value);
}

async function rawGetStorage(
  rpc: RpcSendProvider,
  address: string,
  position: string,
  blockTag: string
): Promise<string> {
  const value = await rpc.send(
    "eth_getStorageAt",
    [address, position, blockTag]
  );

  if (typeof value !== "string") {
    throw new Error("eth_getStorageAt returned a non-string result");
  }

  return value;
}

function rpcCallTransaction(
  input: {
    from?: string;
    to: string;
    data: string;
    value: bigint;
  }
) {
  return {
    ...(input.from ? { from: input.from } : {}),
    to: input.to,
    data: input.data,
    value: toBeHex(input.value)
  };
}

async function detectProxyIdentity(
  rpc: RpcSendProvider,
  target: string,
  code: string,
  blockTag: string,
  rpcSecrets: readonly string[] = []
): Promise<ProxyIdentity> {
  // Custom proxy layouts are unsupported.
  if (code === "0x") {
    return {
      assessment: "not-detected",
      kind: "none"
    };
  }

  const minimal = code.toLowerCase().match(
    /^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/
  );

  if (minimal) {
    const implementation = getAddress(
      `0x${minimal[1]}`
    );
    const implementationCode = await rawGetCode(
      rpc,
      implementation,
      blockTag
    );

    return {
      assessment: "detected",
      kind: "eip1167",
      implementation,
      implementationCodeHash:
        keccak256(implementationCode)
    };
  }

  try {
    const [implementationSlot, beaconSlot] =
      await Promise.all([
        rawGetStorage(
          rpc,
          target,
          EIP1967_IMPLEMENTATION_SLOT,
          blockTag
        ),
        rawGetStorage(
          rpc,
          target,
          EIP1967_BEACON_SLOT,
          blockTag
        )
      ]);

    const implementation =
      storageAddress(implementationSlot);
    const beacon = storageAddress(beaconSlot);

    if (implementation) {
      const implementationCode = await rawGetCode(
        rpc,
        implementation,
        blockTag
      );

      return {
        assessment: "detected",
        kind: "eip1967",
        implementation,
        implementationCodeHash:
          keccak256(implementationCode)
      };
    }

    if (beacon) {
      return {
        assessment: "detected",
        kind: "eip1967-beacon",
        beacon
      };
    }

    return {
      assessment: "not-detected",
      kind: "none"
    };
  } catch (error) {
    return {
      assessment: "unknown",
      kind: "unknown",
      reason: rpcSecrets.length > 0
        ? sanitizeRpcError(error, rpcSecrets)
        : "Proxy identity inspection failed at the pinned block"
    };
  }
}

export async function inspectOnchainWithProvider(
  input: ChainTransaction,
  network: NetworkConfig,
  provider: Provider,
  rpcSource: string,
  rpcSecrets: readonly string[] = []
): Promise<ChainInspection> {
  if (!hasRpcSend(provider)) {
    throw new Error(
      "snapshot provider must expose send()"
    );
  }

  const to = getAddress(input.to);
  const from = input.from
    ? getAddress(input.from)
    : undefined;
  const data = input.data?.trim() || "0x";
  const value = parseValue(input.valueWei);

  const detectedNetwork =
    await provider.getNetwork();

  if (detectedNetwork.chainId !== network.chainId) {
    throw new Error(
      `RPC chain mismatch: ${detectedNetwork.chainId.toString()}`
    );
  }

  const block = await provider.getBlock("latest");

  if (
    !block ||
    !block.hash ||
    !Number.isSafeInteger(block.number) ||
    !Number.isSafeInteger(block.timestamp)
  ) {
    throw new Error(
      "Unable to obtain a complete execution-chain security snapshot"
    );
  }

  const blockTag = toQuantity(block.number);

  const [code, balance] = await Promise.all([
    rawGetCode(provider, to, blockTag),
    rawGetBalance(provider, to, blockTag)
  ]);

  const transaction =
    rpcCallTransaction({
      from,
      to,
      data,
      value
    });

  let simulation: ChainInspection["simulation"];

  try {
    const result = await provider.send(
      "eth_call",
      [transaction, blockTag]
    );

    if (typeof result !== "string") {
      throw new Error(
        "eth_call returned a non-string result"
      );
    }

    simulation = {
      ok: true,
      result
    };
  } catch (error) {
    simulation = {
      ok: false,
      error: rpcSecrets.length > 0
        ? sanitizeRpcError(error, rpcSecrets)
        : "eth_call failed at the pinned block"
    };
  }

  let gasEstimate: ChainInspection["gasEstimate"];

  try {
    const gas = await provider.estimateGas({
      ...(from ? { from } : {}),
      to,
      data,
      value
    });

    gasEstimate = {
      ok: true,
      gas: gas.toString(),
      advisory: true
    };
  } catch (error) {
    gasEstimate = {
      ok: false,
      error: rpcSecrets.length > 0
        ? sanitizeRpcError(error, rpcSecrets)
        : "gas estimation failed",
      advisory: true
    };
  }

  const isContract = code !== "0x";
  const bytecodeBytes = isContract
    ? Math.max(0, (code.length - 2) / 2)
    : 0;

  const proxy = await detectProxyIdentity(
    provider,
    to,
    code,
    blockTag,
    rpcSecrets
  );

  const confirmedBlock =
    await provider.getBlock(block.number);

  if (
    !confirmedBlock?.hash ||
    confirmedBlock.hash.toLowerCase() !==
      block.hash.toLowerCase()
  ) {
    throw new Error(
      `Execution-chain snapshot changed during preflight at block ${block.number}`
    );
  }

  return {
    network: {
      key: network.key,
      name: network.name,
      chainId: network.chainId.toString(),
      blockNumber: block.number,
      blockHash: block.hash,
      timestamp: block.timestamp
    },
    destination: {
      address: to,
      kind: isContract
        ? "contract"
        : "externally-owned-account-or-empty",
      balanceWei: balance.toString(),
      bytecodeBytes,
      codeHash: keccak256(code),
      proxy
    },
    transaction: {
      ...(from ? { from } : {}),
      to,
      valueWei: value.toString(),
      calldataBytes:
        Math.max(0, (data.length - 2) / 2)
    },
    simulation,
    gasEstimate,
    rpcSource
  };
}

async function inspectWithProvider(
  input: ChainTransaction,
  network: NetworkConfig,
  active: WorkingProvider
): Promise<ChainInspection> {
  return inspectOnchainWithProvider(
    input,
    network,
    active.provider,
    active.source,
    [active.url]
  );
}

export async function inspectOnchain(
  input: ChainTransaction
): Promise<ChainInspection> {
  if (!isAddress(input.to)) {
    throw new Error(
      "Invalid EVM destination address"
    );
  }

  if (
    input.from !== undefined &&
    !isAddress(input.from)
  ) {
    throw new Error(
      "Invalid EVM sender address"
    );
  }

  const data = input.data?.trim() || "0x";

  validateData(data);
  parseValue(input.valueWei);

  const network = resolveNetwork(input.chain);
  const excludedUrls = new Set<string>();
  const failures: string[] = [];
  const candidates = rpcCandidates(network);

  for (
    let attempt = 0;
    attempt < candidates.length;
    attempt += 1
  ) {
    const active = await findWorkingProvider(
      network,
      excludedUrls
    );

    try {
      return await inspectWithProvider(
        input,
        network,
        active
      );
    } catch (error) {
      const message = errorMessage(
        error,
        active.url
      );

      failures.push(
        `${active.source}: ${message}`
      );

      excludedUrls.add(active.url);
      invalidateProvider(
        network,
        active
      );

      console.warn(
        `[RPC] ${network.key}/${active.source} became unusable: ${message}`
      );
    }
  }

  throw new Error(
    `RPC inspection failed for ${network.name}:\n${failures.join("\n")}`
  );
}

export async function inspectVerifiedOnchain(
  input: ChainTransaction
): Promise<ChainInspection> {
  if (!isAddress(input.to)) {
    throw new Error(
      "Invalid EVM destination address"
    );
  }

  if (
    input.from !== undefined &&
    !isAddress(input.from)
  ) {
    throw new Error(
      "Invalid EVM sender address"
    );
  }

  const data = input.data?.trim() || "0x";
  validateData(data);
  parseValue(input.valueWei);

  const network = resolveNetwork(input.chain);
  const endpoint = trustedRpcForEnforcement(network);
  const provider = new JsonRpcProvider(
    endpoint.url,
    Number(network.chainId),
    { staticNetwork: true }
  );

  try {
    return await inspectOnchainWithProvider(
      input,
      network,
      provider,
      endpoint.source,
      [endpoint.url]
    );
  } catch (error) {
    throw new Error(
      `Trusted RPC inspection failed for ${network.name}: ${sanitizeRpcError(error, [endpoint.url])}`
    );
  } finally {
    provider.destroy();
  }
}
