import assert from "node:assert/strict";
import test from "node:test";

import {
  keccak256,
  type Provider
} from "ethers";

import {
  inspectOnchainWithProvider
} from "./chain.js";

import {
  resolveNetwork
} from "./networks.js";

const TARGET =
  "0x1111111111111111111111111111111111111111";
const IMPLEMENTATION =
  "0x2222222222222222222222222222222222222222";
const IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const BEACON_SLOT =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

function slotAddress(address: string): string {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;
}

test(
  "snapshot uses one block and catches an EIP-1967 proxy",
  async () => {
    const securityTags: string[] = [];
    const targetCode = "0x60006000";
    const implementationCode = "0x60016001";

    const provider = {
      async getNetwork() {
        return { chainId: 1n };
      },
      async getBlock() {
        return {
          number: 123456,
          hash: `0x${"ab".repeat(32)}`,
          timestamp: 1_900_000_000
        };
      },
      async estimateGas() {
        return 21000n;
      },
      async send(method: string, params: Array<unknown>) {
        if (
          method === "eth_getCode" ||
          method === "eth_getBalance" ||
          method === "eth_getStorageAt" ||
          method === "eth_call"
        ) {
          securityTags.push(String(params.at(-1)));
        }

        if (method === "eth_getCode") {
          const address = String(params[0]).toLowerCase();
          if (address === TARGET.toLowerCase()) {
            return targetCode;
          }
          if (address === IMPLEMENTATION.toLowerCase()) {
            return implementationCode;
          }
          return "0x";
        }
        if (method === "eth_getBalance") {
          return "0x0";
        }
        if (method === "eth_call") {
          return "0x";
        }
        if (method === "eth_getStorageAt") {
          const slot = String(params[1]).toLowerCase();
          if (slot === IMPLEMENTATION_SLOT) {
            return slotAddress(IMPLEMENTATION);
          }
          if (slot === BEACON_SLOT) {
            return `0x${"0".repeat(64)}`;
          }
        }
        throw new Error(`Unexpected RPC method ${method}`);
      }
    } as unknown as Provider & {
      send(method: string, params: Array<unknown>): Promise<unknown>;
    };

    const result = await inspectOnchainWithProvider(
      {
        chain: "ethereum",
        from: "0x3333333333333333333333333333333333333333",
        to: TARGET,
        data: "0x",
        valueWei: "0"
      },
      resolveNetwork("ethereum"),
      provider,
      "test-explicit-provider"
    );

    assert.equal(
      result.network.blockHash,
      `0x${"ab".repeat(32)}`
    );
    assert.equal(result.network.timestamp, 1_900_000_000);
    assert.equal(result.destination.proxy.assessment, "detected");
    assert.equal(result.destination.proxy.kind, "eip1967");
    assert.equal(result.destination.proxy.implementation, IMPLEMENTATION);
    assert.equal(
      result.destination.proxy.implementationCodeHash,
      keccak256(implementationCode)
    );

    assert.ok(securityTags.length >= 5);
    assert.deepEqual(
      new Set(securityTags),
      new Set(["0x1e240"])
    );
    assert.equal(result.gasEstimate.advisory, true);
  }
);

test(
  "rejects a reorg during snapshot reads",
  async () => {
    let blockReads = 0;

    const provider = {
      async getNetwork() {
        return { chainId: 1n };
      },
      async getBlock() {
        blockReads += 1;
        return {
          number: 123456,
          hash: blockReads === 1
            ? `0x${"ab".repeat(32)}`
            : `0x${"cd".repeat(32)}`,
          timestamp: 1_900_000_000
        };
      },
      async estimateGas() {
        return 21000n;
      },
      async send(method: string) {
        if (method === "eth_getCode") {
          return "0x";
        }
        if (method === "eth_getBalance") {
          return "0x0";
        }
        if (method === "eth_call") {
          return "0x";
        }
        throw new Error(`Unexpected RPC method ${method}`);
      }
    } as unknown as Provider & {
      send(method: string, params: Array<unknown>): Promise<unknown>;
    };

    await assert.rejects(
      inspectOnchainWithProvider(
        {
          chain: "ethereum",
          from: "0x3333333333333333333333333333333333333333",
          to: TARGET,
          data: "0x",
          valueWei: "0"
        },
        resolveNetwork("ethereum"),
        provider,
        "test-explicit-provider"
      ),
      /snapshot changed during preflight/
    );
  }
);
