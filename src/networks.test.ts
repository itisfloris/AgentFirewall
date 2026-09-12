import test from "node:test";
import assert from "node:assert/strict";

import {
  resolveNetwork,
  trustedRpcForEnforcement
} from "./networks.js";

test("ethereum resolves to chain 1", () => {
  assert.equal(
    resolveNetwork("ethereum").chainId,
    1n
  );
});

test("sepolia resolves to chain 11155111", () => {
  assert.equal(
    resolveNetwork("sepolia").chainId,
    11155111n
  );
});

test("cc3 alias resolves to Creditcoin testnet 102031", () => {
  const network = resolveNetwork("cc3");
  assert.equal(network.key, "creditcoin-testnet");
  assert.equal(network.chainId, 102031n);
});

test("unknown chain does not fall back", () => {
  assert.throws(
    () => resolveNetwork("totally-unknown-chain"),
    /unsupported chain/
  );
});


test("trusted RPC rejects remote http", () => {
  assert.throws(
    () => trustedRpcForEnforcement(
      resolveNetwork("sepolia"),
      {
        SEPOLIA_RPC_URL: "http://rpc.example/v2/SECRET?key=SECRET2"
      } as NodeJS.ProcessEnv
    ),
    /remote HTTP is not allowed/
  );
});

test("trusted RPC permits loopback http", () => {
  const endpoint = trustedRpcForEnforcement(
    resolveNetwork("sepolia"),
    {
      SEPOLIA_RPC_URL: "http://127.0.0.1:8545"
    } as NodeJS.ProcessEnv
  );

  assert.equal(endpoint.url, "http://127.0.0.1:8545");
});

test("trusted RPC keeps the full URL internally", () => {
  const endpoint = trustedRpcForEnforcement(
    resolveNetwork("sepolia"),
    {
      SEPOLIA_RPC_URL: "https://user:password@rpc.example/v2/SECRET?key=SECRET2"
    } as NodeJS.ProcessEnv
  );

  assert.equal(
    endpoint.url,
    "https://user:password@rpc.example/v2/SECRET?key=SECRET2"
  );
});
