import test from "node:test";
import assert from "node:assert/strict";

import { Interface } from "ethers";

import {
  commitmentFromActualEffect,
  commitmentFromDeclaredIntent
} from "./authorization.js";

import {
  decodeActualEffect,
  type DeclaredIntent
} from "./intent.js";

const TOKEN =
  "0x2222222222222222222222222222222222222222";
const SENDER =
  "0x5555555555555555555555555555555555555555";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const TARGET_CODE_HASH =
  `0x${"12".repeat(32)}`;
const OTHER_CODE_HASH =
  `0x${"34".repeat(32)}`;
const VALID_UNTIL = "2000000000";

const iface = new Interface([
  "function approve(address spender,uint256 amount)"
]);

function declared(
  amountRaw = "1",
  executionNonce = "7",
  targetCodeHash = TARGET_CODE_HASH,
  validUntil = VALID_UNTIL
): DeclaredIntent {
  return {
    executionChainId: "1",
    sender: SENDER,
    executionNonce,
    validUntil,
    targetCodeHash,
    action: "erc20_approve",
    target: TOKEN,
    asset: {
      kind: "erc20",
      address: TOKEN
    },
    spender: SPENDER,
    amountRaw,
    method: "approve(address,uint256)"
  };
}

function actual(
  amount: bigint,
  nonce = "7",
  valueWei = "0"
) {
  return decodeActualEffect({
    chain: "ethereum",
    from: SENDER,
    to: TOKEN,
    nonce,
    valueWei,
    data:
      iface.encodeFunctionData(
        "approve",
        [SPENDER, amount]
      )
  });
}

test(
  "intent and decoded tx share the v3 commitment",
  () => {
    assert.equal(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(1n),
        TARGET_CODE_HASH,
        VALID_UNTIL
      )
    );
  }
);

test(
  "amount mutation changes the authorization commitment",
  () => {
    assert.notEqual(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(2n),
        TARGET_CODE_HASH,
        VALID_UNTIL
      )
    );
  }
);

test(
  "nonce changes the commitment",
  () => {
    assert.notEqual(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(1n, "8"),
        TARGET_CODE_HASH,
        VALID_UNTIL
      )
    );
  }
);

test(
  "code hash changes the commitment",
  () => {
    assert.notEqual(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(1n),
        OTHER_CODE_HASH,
        VALID_UNTIL
      )
    );
  }
);

test(
  "expiry changes the commitment",
  () => {
    assert.notEqual(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(1n),
        TARGET_CODE_HASH,
        "2000000001"
      )
    );
  }
);

test(
  "native value affects the commitment",
  () => {
    assert.notEqual(
      commitmentFromDeclaredIntent(
        declared()
      ),
      commitmentFromActualEffect(
        actual(1n, "7", "1"),
        TARGET_CODE_HASH,
        VALID_UNTIL
      )
    );
  }
);

test(
  "commitment requires sender",
  () => {
    const intent = declared();
    delete intent.sender;

    assert.throws(
      () => commitmentFromDeclaredIntent(intent),
      /exact sender/
    );
  }
);

test(
  "commitment requires execution nonce",
  () => {
    const intent = declared();
    delete intent.executionNonce;

    assert.throws(
      () => commitmentFromDeclaredIntent(intent),
      /executionNonce/
    );
  }
);

test(
  "verified authorization commitment requires an expiry",
  () => {
    const intent = declared();
    delete intent.validUntil;

    assert.throws(
      () => commitmentFromDeclaredIntent(intent),
      /validUntil/
    );
  }
);

test(
  "commitment requires code hash",
  () => {
    const intent = declared();
    delete intent.targetCodeHash;

    assert.throws(
      () => commitmentFromDeclaredIntent(intent),
      /targetCodeHash/
    );
  }
);
