import assert from "node:assert/strict";

import {
  inspectOnchain
} from "./chain.js";

const WETH =
  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

console.log(
  "Connecting to Ethereum Mainnet..."
);

const result =
  await inspectOnchain({
    to: WETH,
    data: "0x",
    valueWei: "0"
  });

console.log(
  JSON.stringify(
    result,
    null,
    2
  )
);

assert.equal(
  result.network.chainId,
  "1"
);

assert.equal(
  result.destination.kind,
  "contract"
);

assert.ok(
  result.destination.bytecodeBytes > 0
);

console.log("");
console.log(
  "LIVE RPC TEST PASSED"
);
