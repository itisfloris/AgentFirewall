import {
  Contract,
  JsonRpcProvider,
  isHexString
} from "ethers";

export const BLOCK_PROVER_ADDRESS =
  "0x0000000000000000000000000000000000000FD2";

const BLOCK_PROVER_ABI = [
  {
    type: "function",
    name: "verifyAndEmit",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainKey", type: "uint64" },
      { name: "height", type: "uint64" },
      { name: "encodedTransaction", type: "bytes" },
      {
        name: "merkleProof",
        type: "tuple",
        components: [
          { name: "root", type: "bytes32" },
          {
            name: "siblings",
            type: "tuple[]",
            components: [
              { name: "hash", type: "bytes32" },
              { name: "isLeft", type: "bool" }
            ]
          }
        ]
      },
      {
        name: "continuityProof",
        type: "tuple",
        components: [
          { name: "lowerEndpointDigest", type: "bytes32" },
          { name: "roots", type: "bytes32[]" }
        ]
      }
    ],
    outputs: [
      { name: "", type: "bool" }
    ]
  }
] as const;

export type AttestcoinProof = {
  chainKey: bigint;
  headerNumber: bigint;
  txBytes: string;
  merkleProof: {
    root: string;
    siblings: Array<{
      hash: string;
      isLeft: boolean;
    }>;
  };
  continuityProof: {
    lowerEndpointDigest: string;
    roots: string[];
  };
};

type RecordValue = Record<string, unknown>;

function asRecord(
  value: unknown,
  field: string
): RecordValue {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new Error(`${field} must be an object`);
  }

  return value as RecordValue;
}

function pick(
  record: RecordValue,
  ...names: string[]
): unknown {
  for (const name of names) {
    if (record[name] !== undefined) {
      return record[name];
    }
  }

  return undefined;
}

function uint64(
  value: unknown,
  field: string
): bigint {
  let parsed: bigint;

  try {
    parsed = BigInt(
      value as bigint | number | string
    );
  } catch {
    throw new Error(`${field} must be an unsigned integer`);
  }

  if (parsed < 0n || parsed >= (1n << 64n)) {
    throw new Error(`${field} must fit uint64`);
  }

  return parsed;
}

function bytes32(
  value: unknown,
  field: string
): string {
  if (
    typeof value !== "string" ||
    !isHexString(value, 32)
  ) {
    throw new Error(`${field} must be exactly 32 bytes`);
  }

  return value;
}

function hexBytes(
  value: unknown,
  field: string
): string {
  if (
    typeof value !== "string" ||
    !isHexString(value)
  ) {
    throw new Error(`${field} must be hex bytes`);
  }

  return value;
}

function unwrapProofResponse(
  raw: unknown
): RecordValue {
  let current = asRecord(raw, "proof response");

  for (const key of ["data", "proof", "result"]) {
    const nested = current[key];
    if (
      nested &&
      typeof nested === "object" &&
      !Array.isArray(nested)
    ) {
      const candidate = nested as RecordValue;
      if (
        pick(candidate, "chainKey", "chain_key") !== undefined ||
        pick(candidate, "txBytes", "tx_bytes", "encodedTransaction", "encoded_transaction") !== undefined
      ) {
        current = candidate;
        break;
      }
    }
  }

  return current;
}

export function normalizeAttestcoinProof(
  raw: unknown,
  fallbackChainKey?: bigint | number
): AttestcoinProof {
  const proof = unwrapProofResponse(raw);

  const merkle = asRecord(
    pick(
      proof,
      "merkleProof",
      "merkle_proof",
      "transactionMerkleProof",
      "transaction_merkle_proof"
    ),
    "proof.merkleProof"
  );

  const continuity = asRecord(
    pick(
      proof,
      "continuityProof",
      "continuity_proof"
    ),
    "proof.continuityProof"
  );

  const rawSiblings = pick(
    merkle,
    "siblings",
    "entries"
  );

  if (!Array.isArray(rawSiblings)) {
    throw new Error("proof.merkleProof.siblings must be an array");
  }

  const siblings = rawSiblings.map(
    (rawSibling, index) => {
      const sibling = asRecord(
        rawSibling,
        `proof.merkleProof.siblings[${index}]`
      );

      const isLeft = pick(
        sibling,
        "isLeft",
        "is_left"
      );

      if (typeof isLeft !== "boolean") {
        throw new Error(
          `proof.merkleProof.siblings[${index}].isLeft must be boolean`
        );
      }

      return {
        hash: bytes32(
          pick(sibling, "hash", "digest"),
          `proof.merkleProof.siblings[${index}].hash`
        ),
        isLeft
      };
    }
  );

  const rawRoots = pick(
    continuity,
    "roots",
    "continuityRoots",
    "continuity_roots"
  );

  if (!Array.isArray(rawRoots)) {
    throw new Error("proof.continuityProof.roots must be an array");
  }

  const chainKey =
    pick(proof, "chainKey", "chain_key") ??
    fallbackChainKey;

  if (chainKey === undefined) {
    throw new Error("proof.chainKey is missing");
  }

  return {
    chainKey: uint64(chainKey, "proof.chainKey"),
    headerNumber: uint64(
      pick(
        proof,
        "headerNumber",
        "header_number",
        "blockNumber",
        "block_number",
        "height"
      ),
      "proof.headerNumber"
    ),
    txBytes: hexBytes(
      pick(
        proof,
        "txBytes",
        "tx_bytes",
        "encodedTransaction",
        "encoded_transaction",
        "transactionBytes",
        "transaction_bytes"
      ),
      "proof.txBytes"
    ),
    merkleProof: {
      root: bytes32(
        pick(merkle, "root", "merkleRoot", "merkle_root"),
        "proof.merkleProof.root"
      ),
      siblings
    },
    continuityProof: {
      lowerEndpointDigest: bytes32(
        pick(
          continuity,
          "lowerEndpointDigest",
          "lower_endpoint_digest"
        ),
        "proof.continuityProof.lowerEndpointDigest"
      ),
      roots: rawRoots.map(
        (root, index) =>
          bytes32(
            root,
            `proof.continuityProof.roots[${index}]`
          )
      )
    }
  };
}

function positiveDuration(
  raw: string | undefined,
  fallback: number,
  name: string
): number {
  if (!raw?.trim()) {
    return fallback;
  }

  if (!/^\d+$/.test(raw.trim())) {
    throw new Error(`${name} must be an unsigned integer in milliseconds`);
  }

  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }

  return value;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function fetchAttestcoinProof(params: {
  proofBuilderUrl: string;
  chainKey: number | bigint;
  transactionHash: string;
}): Promise<AttestcoinProof> {
  const baseUrl = params.proofBuilderUrl.replace(/\/+$/, "");
  const url =
    `${baseUrl}/api/v1/proof-by-tx/${params.chainKey.toString()}/${encodeURIComponent(params.transactionHash)}`;

  const timeoutMs = positiveDuration(
    process.env.ATTESTCOIN_PROOF_WAIT_TIMEOUT_MS,
    1_200_000,
    "ATTESTCOIN_PROOF_WAIT_TIMEOUT_MS"
  );

  const pollMs = positiveDuration(
    process.env.ATTESTCOIN_PROOF_POLL_MS,
    15_000,
    "ATTESTCOIN_PROOF_POLL_MS"
  );

  const deadline = Date.now() + timeoutMs;
  let lastStatus = "no response";

  while (Date.now() < deadline) {
    const remaining = Math.max(1, deadline - Date.now());
    const requestTimeout = Math.min(30_000, remaining);
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      requestTimeout
    );

    try {
      const response = await fetch(url, {
        headers: {
          accept: "application/json"
        },
        signal: controller.signal
      });

      lastStatus = `${response.status} ${response.statusText}`.trim();

      if (response.ok) {
        return normalizeAttestcoinProof(
          await response.json(),
          params.chainKey
        );
      }

      const body = (await response.text()).slice(0, 2_000);
      let explicitlyRetriable = false;

      try {
        const errorBody = JSON.parse(body) as Record<string, unknown>;
        explicitlyRetriable =
          errorBody.retriable === true ||
          errorBody.retryable === true ||
          (
            errorBody.error !== null &&
            typeof errorBody.error === "object" &&
            (
              (errorBody.error as Record<string, unknown>).retriable === true ||
              (errorBody.error as Record<string, unknown>).retryable === true
            )
          );
      } catch {
        explicitlyRetriable = false;
      }

      const transientStatus = [
        202,
        404,
        409,
        425,
        429,
        500,
        502,
        503,
        504
      ].includes(response.status);

      if (!explicitlyRetriable && !transientStatus) {
        throw new Error(
          `Attestcoin Proof Builder rejected the request (${lastStatus}): ${body}`
        );
      }

      lastStatus = body
        ? `${lastStatus}: ${body.slice(0, 500)}`
        : lastStatus;
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith(
          "Attestcoin Proof Builder rejected"
        )
      ) {
        throw error;
      }

      lastStatus =
        error instanceof Error
          ? `${error.name}: ${error.message}`
          : String(error);
    } finally {
      clearTimeout(timer);
    }

    const left = deadline - Date.now();
    if (left <= 0) {
      break;
    }

    await sleep(Math.min(pollMs, left));
  }

  throw new Error(
    `Timed out waiting for Attestcoin proof for ${params.transactionHash}. Last result: ${lastStatus}`
  );
}

export async function verifyAttestcoinProof(
  provider: JsonRpcProvider,
  proof: AttestcoinProof
): Promise<boolean> {
  const prover = new Contract(
    BLOCK_PROVER_ADDRESS,
    BLOCK_PROVER_ABI,
    provider
  );

  const verified =
    await prover.verifyAndEmit.staticCall(
      proof.chainKey,
      proof.headerNumber,
      proof.txBytes,
      proof.merkleProof,
      proof.continuityProof
    );

  return Boolean(verified);
}
