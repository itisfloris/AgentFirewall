import test from "node:test";
import assert from "node:assert/strict";

import {
  Interface,
  MaxUint256
} from "ethers";

import {
  commitmentFromDeclaredIntent
} from "./authorization.js";

import type {
  DeclaredIntent
} from "./intent.js";

import type {
  ChainInspector
} from "./preflight.js";

import {
  normalizeSemanticRegistryTrustConfig,
  runVerifiedPreflight,
  type VerifiedAuthorizationReader
} from "./verified-preflight.js";

const AUTHORIZATION_ID =
  `0x${"ab".repeat(32)}`;
const TOKEN =
  "0x2222222222222222222222222222222222222222";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const ATTACKER =
  "0x9999999999999999999999999999999999999999";
const SENDER =
  "0x5555555555555555555555555555555555555555";
const TARGET_CODE_HASH =
  `0x${"12".repeat(32)}`;
const MUTATED_CODE_HASH =
  `0x${"34".repeat(32)}`;
const VALID_UNTIL = "2000000000";

const iface = new Interface([
  "function approve(address spender,uint256 amount)"
]);

function intent(
  overrides: Partial<DeclaredIntent> = {}
): DeclaredIntent {
  return {
    executionChainId: "1",
    sender: SENDER,
    executionNonce: "7",
    validUntil: VALID_UNTIL,
    targetCodeHash: TARGET_CODE_HASH,
    action: "erc20_approve",
    target: TOKEN,
    asset: {
      kind: "erc20",
      address: TOKEN
    },
    spender: SPENDER,
    amountRaw: "1",
    method: "approve(address,uint256)",
    ...overrides
  } as DeclaredIntent;
}

function inspectorWithCodeHash(
  codeHash = TARGET_CODE_HASH,
  options: {
    timestamp?: number;
    proxy?: {
      assessment: "not-detected" | "detected" | "unknown";
      kind: "none" | "eip1967" | "eip1967-beacon" | "eip1167" | "unknown";
    };
  } = {}
): ChainInspector {
  return async (transaction) => ({
    network: {
      key: "ethereum",
      name: "Ethereum Mainnet",
      chainId: "1",
      blockNumber: 123456,
      blockHash: `0x${"56".repeat(32)}`,
      timestamp: options.timestamp ?? 1_900_000_000
    },
    destination: {
      address: transaction.to,
      kind: "contract",
      balanceWei: "0",
      bytecodeBytes: 100,
      codeHash,
      proxy: options.proxy ?? {
        assessment: "not-detected" as const,
        kind: "none" as const
      }
    },
    transaction: {
      from: transaction.from,
      to: transaction.to,
      valueWei: transaction.valueWei ?? "0",
      calldataBytes:
        Math.max(
          0,
          ((transaction.data ?? "0x").length - 2) / 2
        )
    },
    simulation: {
      ok: true as const,
      result: "0x01"
    },
    gasEstimate: {
      ok: true as const,
      gas: "50000",
      advisory: true as const
    },
    rpcSource: "test-double"
  });
}

function tx(
  amount = 1n,
  nonce: string | null = "7",
  spender = SPENDER,
  data?: string
) {
  return {
    chain: "ethereum",
    from: SENDER,
    to: TOKEN,
    ...(nonce === null ? {} : { nonce }),
    valueWei: "0",
    data:
      data ??
      iface.encodeFunctionData(
        "approve",
        [spender, amount]
      )
  };
}

function readerFor(
  declared = intent(),
  options: {
    commitment?: string;
    verified?: boolean;
    validUntil?: string;
  } = {}
): VerifiedAuthorizationReader {
  const commitment =
    options.commitment ??
    commitmentFromDeclaredIntent(declared);

  return {
    async getAuthorization(
      authorizationId
    ) {
      return {
        authorizationId,
        commitment,
        verified: options.verified ?? true,
        sourceChainKey: "1",
        sourceBlockNumber: "123",
        transactionIndex: "4",
        validUntil:
          options.validUntil ??
          declared.validUntil ??
          VALID_UNTIL,
        registryAddress:
          "0x7777777777777777777777777777777777777777",
        creditcoinChainId: "102031",
        rpcSource: "test-double"
      };
    }
  };
}

test(
  "matching verified execution is allowed",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared),
      { requireKnownCalldata: true },
      inspectorWithCodeHash()
    );

    assert.equal(result.authorization.ok, true);
    assert.equal(result.integrity.ok, true);
    assert.equal(result.onchain.simulation.ok, true);
    assert.equal(result.decision, "ALLOW");
  }
);

test(
  "registry commitment mismatch blocks",
  async () => {
    const declared = intent();
    const wrongCommitment = `0x${"cd".repeat(32)}`;
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared, { commitment: wrongCommitment }),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.equal(result.score, 100);
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_DECLARED_COMMITMENT_MISMATCH"
    ));
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_ACTUAL_COMMITMENT_MISMATCH"
    ));
  }
);

test(
  "unverified registry record blocks",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared, { verified: false }),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_AUTHORIZATION_NOT_VERIFIED"
    ));
  }
);

test(
  "missing verified authorization is rejected",
  async () => {
    const reader: VerifiedAuthorizationReader = {
      async getAuthorization() {
        return null;
      }
    };

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      intent(),
      tx(),
      reader,
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_AUTHORIZATION_NOT_FOUND"
    ));
  }
);

test(
  "registry RPC failure is rejected",
  async () => {
    const reader: VerifiedAuthorizationReader = {
      async getAuthorization() {
        throw new Error("RPC unavailable");
      }
    };

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      intent(),
      tx(),
      reader,
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_AUTHORIZATION_UNAVAILABLE"
    ));
  }
);

test(
  "mutated amount cannot reuse the safe commitment",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(MaxUint256),
      readerFor(declared),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.equal(result.onchain.simulation.ok, true);
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_ACTUAL_COMMITMENT_MISMATCH"
    ));
    assert.ok(result.findings.some(
      finding => finding.code === "AMOUNT_MISMATCH"
    ));
  }
);

test(
  "spender mutation cannot reuse a verified commitment",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(1n, "7", ATTACKER),
      readerFor(declared),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.findings.some(
      finding => finding.code === "SPENDER_MISMATCH"
    ));
  }
);

test(
  "nonce replay blocks",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(1n, "8"),
      readerFor(declared),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.equal(result.onchain.simulation.ok, true);
    assert.ok(result.findings.some(
      finding => finding.code === "EXECUTION_NONCE_MISMATCH"
    ));
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_ACTUAL_COMMITMENT_MISMATCH"
    ));
  }
);

test(
  "missing execution nonce blocks",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(1n, null),
      readerFor(declared),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.findings.some(
      finding => finding.code === "EXECUTION_NONCE_MISSING"
    ));
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "ACTUAL_AUTHORIZATION_UNCOMMITTABLE"
    ));
  }
);

test(
  "expired authorization blocks",
  async () => {
    const declared = intent({ validUntil: "100" } as Partial<DeclaredIntent>);
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared, { validUntil: "100" }),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_AUTHORIZATION_EXPIRED"
    ));
  }
);

test(
  "expiry mismatch blocks",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared, { validUntil: "2000000001" }),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_VALID_UNTIL_MISMATCH"
    ));
  }
);

test(
  "verified preflight requires expiry",
  async () => {
    const declared = intent();
    delete declared.validUntil;

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(intent()),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "DECLARED_VALID_UNTIL_MISSING"
    ));
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "DECLARED_AUTHORIZATION_UNCOMMITTABLE"
    ));
  }
);

test(
  "target code change blocks",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared),
      {},
      inspectorWithCodeHash(MUTATED_CODE_HASH)
    );

    assert.equal(result.decision, "BLOCK");
    assert.equal(result.onchain.simulation.ok, true);
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "TARGET_CODE_HASH_MISMATCH"
    ));
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_ACTUAL_COMMITMENT_MISMATCH"
    ));
  }
);

test(
  "verified preflight requires target code hash",
  async () => {
    const declared = intent();
    delete declared.targetCodeHash;

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(intent()),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "DECLARED_TARGET_CODE_HASH_MISSING"
    ));
  }
);

test(
  "verified preflight requires sender",
  async () => {
    const declared = intent();
    delete declared.sender;

    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(intent()),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "DECLARED_AUTHORIZATION_UNCOMMITTABLE"
    ));
  }
);


test(
  "registry source anchors are checked",
  () => {
    const config =
      normalizeSemanticRegistryTrustConfig(
        "1",
        "0x4444444444444444444444444444444444444444"
      );

    assert.deepEqual(
      config,
      {
        sourceChainKey: "1",
        sourceChainId: "11155111",
        authorizationSource:
          "0x4444444444444444444444444444444444444444"
      }
    );
  }
);

test(
  "bad registry source anchors are rejected",
  () => {
    assert.throws(
      () =>
        normalizeSemanticRegistryTrustConfig(
          undefined,
          "0x4444444444444444444444444444444444444444"
        ),
      /SOURCE_CHAIN_KEY/
    );

    assert.throws(
      () =>
        normalizeSemanticRegistryTrustConfig(
          "18446744073709551616",
          "0x4444444444444444444444444444444444444444"
        ),
      /fit uint64/
    );

    assert.throws(
      () =>
        normalizeSemanticRegistryTrustConfig(
          "1",
          undefined
        ),
      /AUTHORIZATION_SOURCE_ADDRESS/
    );
  }
);


test(
  "expiry is inclusive at validUntil",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared),
      {},
      inspectorWithCodeHash(
        TARGET_CODE_HASH,
        { timestamp: Number(VALID_UNTIL) }
      )
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "VERIFIED_AUTHORIZATION_EXPIRED"
    ));
  }
);

test(
  "upgradeable proxy is blocked",
  async () => {
    const declared = intent();
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(),
      readerFor(declared),
      {},
      inspectorWithCodeHash(
        TARGET_CODE_HASH,
        {
          proxy: {
            assessment: "detected",
            kind: "eip1967"
          }
        }
      )
    );

    assert.equal(result.decision, "BLOCK");
    assert.ok(result.authorization.findings.some(
      finding => finding.code === "UPGRADEABLE_PROXY_UNSUPPORTED"
    ));
  }
);

test(
  "verified authorization remains subject to the local deny layer",
  async () => {
    const declared = intent({
      amountRaw: MaxUint256.toString()
    });
    const result = await runVerifiedPreflight(
      AUTHORIZATION_ID,
      declared,
      tx(MaxUint256),
      readerFor(declared),
      {},
      inspectorWithCodeHash()
    );

    assert.equal(result.authorization.ok, true);
    assert.equal(result.integrity.ok, true);
    assert.equal(result.decision, "BLOCK");
    assert.ok(result.findings.some(
      finding => finding.code === "UNLIMITED_APPROVAL"
    ));
  }
);
