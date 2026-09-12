export type NetworkKey =
  | "ethereum"
  | "sepolia"
  | "creditcoin-testnet";

export type NetworkConfig = {
  key: NetworkKey;
  name: string;
  chainId: bigint;
  rpcEnvVar: string;
  publicRpcs: ReadonlyArray<{
    source: string;
    url: string;
  }>;
};

const NETWORKS: Record<NetworkKey, NetworkConfig> = {
  ethereum: {
    key: "ethereum",
    name: "Ethereum Mainnet",
    chainId: 1n,
    rpcEnvVar: "ETH_RPC_URL",
    publicRpcs: [
      {
        source: "publicnode",
        url: "https://ethereum-rpc.publicnode.com"
      },
      {
        source: "drpc",
        url: "https://eth.drpc.org"
      },
      {
        source: "cloudflare",
        url: "https://cloudflare-eth.com/v1/mainnet"
      }
    ]
  },

  sepolia: {
    key: "sepolia",
    name: "Ethereum Sepolia",
    chainId: 11155111n,
    rpcEnvVar: "SEPOLIA_RPC_URL",
    publicRpcs: [
      {
        source: "publicnode",
        url: "https://ethereum-sepolia-rpc.publicnode.com"
      },
      {
        source: "drpc",
        url: "https://sepolia.drpc.org"
      }
    ]
  },

  "creditcoin-testnet": {
    key: "creditcoin-testnet",
    name: "Creditcoin CC3 Testnet",
    chainId: 102031n,
    rpcEnvVar: "CREDITCOIN_RPC_URL",
    publicRpcs: [
      {
        source: "creditcoin-official",
        url: "https://rpc.cc3-testnet.creditcoin.network"
      }
    ]
  }
};

const ALIASES = new Map<string, NetworkKey>([
  ["ethereum", "ethereum"],
  ["eth", "ethereum"],
  ["mainnet", "ethereum"],
  ["1", "ethereum"],

  ["sepolia", "sepolia"],
  ["ethereum-sepolia", "sepolia"],
  ["11155111", "sepolia"],

  ["creditcoin-testnet", "creditcoin-testnet"],
  ["creditcoin", "creditcoin-testnet"],
  ["cc3", "creditcoin-testnet"],
  ["cc3-testnet", "creditcoin-testnet"],
  ["102031", "creditcoin-testnet"]
]);

export function resolveNetwork(
  chain: string | undefined
): NetworkConfig {
  const raw =
    (chain ?? "ethereum")
      .trim()
      .toLowerCase();

  const key =
    ALIASES.get(raw);

  if (!key) {
    throw new Error(
      `unsupported chain: '${chain ?? ""}'`
    );
  }

  return NETWORKS[key];
}

export function rpcCandidates(
  network: NetworkConfig
) {
  const custom =
    process.env[network.rpcEnvVar]?.trim();

  const entries = [
    ...(custom
      ? [{
          source: `${network.key}-custom`,
          url: custom
        }]
      : []),
    ...network.publicRpcs
  ];

  const seen = new Set<string>();

  return entries.filter((entry) => {
    if (seen.has(entry.url)) {
      return false;
    }

    seen.add(entry.url);
    return true;
  });
}


function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "");

  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "::1"
  );
}

export function validateTrustedRpcUrl(
  rawUrl: string,
  configName = "trusted RPC"
): string {
  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(
      `${configName}: invalid URL`
    );
  }

  if (
    parsed.protocol !== "https:" &&
    parsed.protocol !== "http:"
  ) {
    throw new Error(
      `${configName}: HTTPS required (HTTP is loopback-only)`
    );
  }

  if (
    parsed.protocol === "http:" &&
    !isLoopbackHost(parsed.hostname)
  ) {
    throw new Error(
      `${configName}: remote HTTP is not allowed`
    );
  }

  return rawUrl;
}

export type TrustedRpcEndpoint = {
  source: string;
  url: string;
};

export function trustedRpcForEnforcement(
  network: NetworkConfig,
  env: NodeJS.ProcessEnv = process.env
): TrustedRpcEndpoint {
  const configured =
    env[network.rpcEnvVar]?.trim();

  if (configured) {
    return {
      source: `${network.key}-trusted-config`,
      url: validateTrustedRpcUrl(
        configured,
        network.rpcEnvVar
      )
    };
  }

  if (env.AGENTFIREWALL_ALLOW_PUBLIC_RPC_FOR_DEMO === "true") {
    const fallback = network.publicRpcs[0];

    if (!fallback) {
      throw new Error(
        `No public RPC is configured for ${network.name}`
      );
    }

    return {
      source: `${fallback.source}-demo-opt-in`,
      url: validateTrustedRpcUrl(
        fallback.url,
        `${network.key} public demo RPC`
      )
    };
  }

  throw new Error(
    `${network.rpcEnvVar} is required for verified sends`
  );
}

export function supportedNetworks(): NetworkConfig[] {
  return Object.values(NETWORKS);
}
