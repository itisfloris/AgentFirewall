import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeAttestcoinProof
} from "./attestcoin-native.js";

const HASH_A = `0x${"11".repeat(32)}`;
const HASH_B = `0x${"22".repeat(32)}`;
const HASH_C = `0x${"33".repeat(32)}`;
const TX_BYTES = "0x1234";

test(
  "normalizes the current Proof Builder camelCase response",
  () => {
    const proof = normalizeAttestcoinProof({
      chainKey: 1,
      headerNumber: 12345,
      txBytes: TX_BYTES,
      merkleProof: {
        root: HASH_A,
        siblings: [
          {
            hash: HASH_B,
            isLeft: true
          }
        ]
      },
      continuityProof: {
        lowerEndpointDigest: HASH_C,
        roots: [HASH_A, HASH_B]
      }
    });

    assert.equal(proof.chainKey, 1n);
    assert.equal(proof.headerNumber, 12345n);
    assert.equal(proof.txBytes, TX_BYTES);
    assert.equal(proof.merkleProof.siblings[0]?.isLeft, true);
    assert.deepEqual(
      proof.continuityProof.roots,
      [HASH_A, HASH_B]
    );
  }
);

test(
  "normalizes wrapped snake_case proof data defensively",
  () => {
    const proof = normalizeAttestcoinProof({
      data: {
        chain_key: "1",
        header_number: "88",
        tx_bytes: TX_BYTES,
        merkle_proof: {
          merkle_root: HASH_A,
          siblings: [
            {
              hash: HASH_B,
              is_left: false
            }
          ]
        },
        continuity_proof: {
          lower_endpoint_digest: HASH_C,
          roots: []
        }
      }
    });

    assert.equal(proof.chainKey, 1n);
    assert.equal(proof.headerNumber, 88n);
    assert.equal(proof.merkleProof.root, HASH_A);
    assert.equal(proof.merkleProof.siblings[0]?.isLeft, false);
  }
);

test(
  "rejects malformed proof hashes before native verification",
  () => {
    assert.throws(
      () =>
        normalizeAttestcoinProof({
          chainKey: 1,
          headerNumber: 1,
          txBytes: TX_BYTES,
          merkleProof: {
            root: "0x12",
            siblings: []
          },
          continuityProof: {
            lowerEndpointDigest: HASH_C,
            roots: []
          }
        }),
      /exactly 32 bytes/
    );
  }
);
