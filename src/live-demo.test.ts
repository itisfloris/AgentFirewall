import assert from "node:assert/strict";
import test from "node:test";

import {
  ZeroAddress,
  keccak256
} from "ethers";

import {
  buildNativeLiveDemoPlan
} from "./live-demo.js";

const SENDER =
  "0x5555555555555555555555555555555555555555";
const RECIPIENT =
  "0x6666666666666666666666666666666666666666";

const EMPTY_CODE_HASH =
  keccak256("0x");

test(
  "demo uses the next Sepolia nonce",
  () => {
    const plan =
      buildNativeLiveDemoPlan({
        sender: SENDER,
        recipient: RECIPIENT,
        currentSepoliaNonce: 7n,
        targetCodeHash:
          EMPTY_CODE_HASH,
        nowSeconds: 2_000_000_000n,
        validitySeconds: 3600n,
        amountWei: 1n
      });

    assert.equal(
      plan.authorization.executionNonce,
      "8"
    );
    assert.equal(
      plan.transaction.nonce,
      "8"
    );
    assert.equal(
      plan.declaredIntent.executionNonce,
      "8"
    );
    assert.equal(
      plan.authorization.validUntil,
      "2000003600"
    );
    assert.equal(
      plan.authorization.executionChainId,
      "11155111"
    );
    assert.equal(
      plan.authorization.actionCode,
      1
    );
    assert.equal(
      plan.authorization.asset,
      ZeroAddress
    );
    assert.equal(
      plan.authorization.counterpartyA,
      RECIPIENT
    );
    assert.equal(
      plan.authorization.amountOrFlag,
      "1"
    );
  }
);

test(
  "demo mutation changes recipient only",
  () => {
    const plan =
      buildNativeLiveDemoPlan({
        sender: SENDER,
        recipient: RECIPIENT,
        currentSepoliaNonce: 10,
        targetCodeHash:
          EMPTY_CODE_HASH,
        nowSeconds: 2_000_000_000,
        amountWei: 1
      });

    assert.notEqual(
      plan.mutatedTransaction.to,
      plan.transaction.to
    );
    assert.equal(
      plan.mutatedTransaction.data,
      "0x"
    );
    assert.equal(
      plan.mutatedTransaction.valueWei,
      "1"
    );
    assert.equal(
      plan.mutatedTransaction.nonce,
      plan.transaction.nonce
    );
  }
);

test(
  "demo rejects a short expiry window",
  () => {
    assert.throws(
      () =>
        buildNativeLiveDemoPlan({
          sender: SENDER,
          recipient: RECIPIENT,
          currentSepoliaNonce: 1,
          targetCodeHash:
            EMPTY_CODE_HASH,
          nowSeconds: 2_000_000_000,
          validitySeconds: 600
        }),
      /at least 1200/
    );
  }
);
