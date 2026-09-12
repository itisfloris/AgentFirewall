import test from "node:test";
import assert from "node:assert/strict";

import {
  ZeroAddress
} from "ethers";

import {
  assertProofMatchesSourceReceipt,
  authorizationSourceInterface,
  calculateTransactionIndex,
  computeProofTransactionKey
} from "./attestcoin-b2.js";

const SENDER =
  "0x5555555555555555555555555555555555555555";
const TOKEN =
  "0x2222222222222222222222222222222222222222";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const TARGET_CODE_HASH =
  `0x${"12".repeat(32)}`;

function approvalTuple() {
  return {
    executionChainId: 1n,
    sender: SENDER,
    executionNonce: 7n,
    validUntil: 2000000000n,
    actionCode: 2,
    target: TOKEN,
    targetCodeHash: TARGET_CODE_HASH,
    asset: TOKEN,
    counterpartyA: SPENDER,
    counterpartyB: ZeroAddress,
    amountOrFlag: 1n
  };
}

test(
  "derives tx index from Merkle path",
  () => {
    assert.equal(
      calculateTransactionIndex([
        { isLeft: true },
        { isLeft: false },
        { isLeft: true },
        { isLeft: true }
      ]),
      13n
    );
  }
);

test(
  "rejects oversized tx index paths",
  () => {
    assert.throws(
      () =>
        calculateTransactionIndex(
          Array.from(
            { length: 65 },
            () => ({ isLeft: false })
          )
        ),
      /64 entries/
    );
  }
);

test(
  "proof key includes chain, block and tx index",
  () => {
    const base = computeProofTransactionKey(1, 100, 7);

    assert.notEqual(base, computeProofTransactionKey(2, 100, 7));
    assert.notEqual(base, computeProofTransactionKey(1, 101, 7));
    assert.notEqual(base, computeProofTransactionKey(1, 100, 8));
  }
);

test(
  "AuthorizationSource ABI round-trip",
  () => {
    const calldata =
      authorizationSourceInterface.encodeFunctionData(
        "publishAuthorization",
        [approvalTuple()]
      );

    const decoded =
      authorizationSourceInterface.decodeFunctionData(
        "publishAuthorization",
        calldata
      );

    assert.equal(decoded[0].executionChainId, 1n);
    assert.equal(decoded[0].sender, SENDER);
    assert.equal(decoded[0].executionNonce, 7n);
    assert.equal(decoded[0].validUntil, 2000000000n);
    assert.equal(decoded[0].actionCode, 2n);
    assert.equal(decoded[0].targetCodeHash.toLowerCase(), TARGET_CODE_HASH);
    assert.equal(decoded[0].counterpartyA, SPENDER);
    assert.equal(decoded[0].amountOrFlag, 1n);
  }
);

test(
  "AuthorizationSource binds execution bytes",
  () => {
    assert.ok(
      authorizationSourceInterface.getFunction(
        "computeExecutionBinding"
      )
    );
    assert.ok(
      authorizationSourceInterface.getFunction(
        "computeCommitment"
      )
    );
  }
);

test(
  "AuthorizationPublished indexed fields",
  () => {
    const event =
      authorizationSourceInterface.getEvent(
        "AuthorizationPublished"
      );

    assert.ok(event);
    assert.equal(
      event.inputs.filter(
        (input: { indexed?: boolean | null }) => input.indexed === true
      ).length,
      3
    );
    assert.equal(event.inputs[0].name, "authorizationId");
    assert.equal(event.inputs[1].name, "commitment");
    assert.equal(event.inputs[2].name, "sender");

    const names = event.inputs.map(
      (input: { name: string }) => input.name
    );
    assert.ok(names.includes("executionNonce"));
    assert.ok(names.includes("validUntil"));
    assert.ok(names.includes("targetCodeHash"));
    assert.ok(names.includes("callDataHash"));
    assert.ok(names.includes("nativeValueWei"));
  }
);


test(
  "proof coordinates match the source receipt",
  () => {
    const index =
      assertProofMatchesSourceReceipt({
        proofChainKey: 1,
        expectedChainKey: 1,
        proofHeaderNumber: 12345,
        receiptBlockNumber: 12345,
        siblings: [
          { isLeft: true },
          { isLeft: false },
          { isLeft: true }
        ],
        receiptTransactionIndex: 5
      });

    assert.equal(index, 5n);
  }
);

test(
  "rejects a mismatched proof transaction index",
  () => {
    assert.throws(
      () =>
        assertProofMatchesSourceReceipt({
          proofChainKey: 1,
          expectedChainKey: 1,
          proofHeaderNumber: 12345,
          receiptBlockNumber: 12345,
          siblings: [
            { isLeft: true },
            { isLeft: false },
            { isLeft: true }
          ],
          receiptTransactionIndex: 4
        }),
      /transaction index 5.*receipt index 4/
    );
  }
);

test(
  "rejects wrong proof coordinates",
  () => {
    assert.throws(
      () =>
        assertProofMatchesSourceReceipt({
          proofChainKey: 2,
          expectedChainKey: 1,
          proofHeaderNumber: 100,
          receiptBlockNumber: 100,
          siblings: [],
          receiptTransactionIndex: 0
        }),
      /chainKey 2.*chainKey 1/
    );

    assert.throws(
      () =>
        assertProofMatchesSourceReceipt({
          proofChainKey: 1,
          expectedChainKey: 1,
          proofHeaderNumber: 101,
          receiptBlockNumber: 100,
          siblings: [],
          receiptTransactionIndex: 0
        }),
      /Proof block 101.*receipt block 100/
    );
  }
);
