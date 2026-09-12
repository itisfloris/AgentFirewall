import test from "node:test";
import assert from "node:assert/strict";

import { Interface } from "ethers";

import {
  runIntentPreflight
} from "./intent-preflight.js";

import type {
  DeclaredIntent
} from "./intent.js";

import type {
  ChainInspector
} from "./preflight.js";

const TOKEN =
  "0x2222222222222222222222222222222222222222";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const SENDER =
  "0x5555555555555555555555555555555555555555";

const iface = new Interface([
  "function approve(address spender,uint256 amount)"
]);

const intent: DeclaredIntent = {
  executionChainId: "1",
  sender: SENDER,
  action: "erc20_approve",
  target: TOKEN,
  asset: {
    kind: "erc20",
    address: TOKEN
  },
  spender: SPENDER,
  amountRaw: "1",
  method: "approve(address,uint256)"
};

const fakeSuccessfulInspector: ChainInspector =
  async (transaction) => ({
    network: {
      key: "ethereum",
      name: "Ethereum Mainnet",
      chainId: "1",
      blockNumber: 123456,
      blockHash: `0x${"56".repeat(32)}`,
      timestamp: 1_900_000_000
    },
    destination: {
      address: transaction.to,
      kind: "contract",
      balanceWei: "0",
      bytecodeBytes: 100,
      codeHash: `0x${"12".repeat(32)}`,
      proxy: { assessment: "not-detected" as const, kind: "none" as const }
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

function tx(amount: bigint) {
  return {
    chain: "ethereum",
    from: SENDER,
    to: TOKEN,
    valueWei: "0",
    data:
      iface.encodeFunctionData(
        "approve",
        [SPENDER, amount]
      )
  };
}

test(
  "matching execution passes preflight",
  async () => {
    const result =
      await runIntentPreflight(
        intent,
        tx(1n),
        { requireKnownCalldata: true },
        fakeSuccessfulInspector
      );

    assert.equal(result.integrity.ok, true);
    assert.equal(result.onchain.simulation.ok, true);
    assert.equal(result.decision, "ALLOW");
  }
);

test(
  "simulation does not excuse amount mismatch",
  async () => {
    const result =
      await runIntentPreflight(
        intent,
        tx(2n),
        { requireKnownCalldata: true },
        fakeSuccessfulInspector
      );

    assert.equal(result.onchain.simulation.ok, true);
    assert.equal(result.integrity.decision, "BLOCK");
    assert.equal(result.decision, "BLOCK");
    assert.equal(result.score, 100);
    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "AMOUNT_MISMATCH"
      )
    );
  }
);

test(
  "unknown effect is blocked",
  async () => {
    const result =
      await runIntentPreflight(
        intent,
        {
          chain: "ethereum",
          from: SENDER,
          to: TOKEN,
          data: "0x12345678",
          valueWei: "0"
        },
        {},
        fakeSuccessfulInspector
      );

    assert.equal(result.onchain.simulation.ok, true);
    assert.equal(result.decision, "BLOCK");
    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "UNKNOWN_ACTUAL_EFFECT"
      )
    );
  }
);

test(
  "declared chain mismatch blocks",
  async () => {
    const result =
      await runIntentPreflight(
        {
          ...intent,
          executionChainId: "11155111"
        },
        tx(1n),
        {},
        fakeSuccessfulInspector
      );

    assert.equal(result.decision, "BLOCK");
    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "CHAIN_MISMATCH"
      )
    );
  }
);
