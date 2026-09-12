import test from "node:test";
import assert from "node:assert/strict";

import {
  ZeroAddress,
  id
} from "ethers";

import {
  authorizationSourceInterface
} from "./attestcoin-b2.js";

import {
  AUTHORIZATION_COMMITMENT_DOMAIN,
  AUTHORIZATION_ID_DOMAIN,
  AUTHORIZATION_PUBLISHED_TOPIC,
  VERIFIED_AUTHORIZATION_REGISTRY_ABI,
  expectedEvidenceExecutionBinding,
  linkSolidityBytecode,
  maskSolidityByteRanges,
  parseTrustedAuthorizationEvidence,
  recomputeAuthorizationId,
  recomputeEvidenceCommitment,
  validateSemanticRegistryTrustAnchors,
  validateSourceAuthorizationEvidence,
  verifiedAuthorizationRegistryInterface
} from "./semantic-registry.js";

import type {
  SourceAuthorizationEvidence
} from "./semantic-registry.js";

import {
  readFileSync
} from "node:fs";

const SOURCE =
  "0x4444444444444444444444444444444444444444";
const SENDER =
  "0x5555555555555555555555555555555555555555";
const TOKEN =
  "0x2222222222222222222222222222222222222222";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const AUTHORIZATION_ID =
  `0x${"ab".repeat(32)}`;
const COMMITMENT =
  `0x${"cd".repeat(32)}`;
const TARGET_CODE_HASH =
  `0x${"12".repeat(32)}`;
const CALL_DATA_HASH =
  `0x${"34".repeat(32)}`;


function canonicalEvidence(): SourceAuthorizationEvidence {
  const draft: SourceAuthorizationEvidence = {
    authorizationId: `0x${"00".repeat(32)}`,
    commitment: `0x${"00".repeat(32)}`,
    sender: SENDER,
    nonce: "9",
    executionChainId: "1",
    executionNonce: "7",
    validUntil: "2000000000",
    actionCode: 2,
    target: TOKEN,
    targetCodeHash: TARGET_CODE_HASH,
    asset: TOKEN,
    counterpartyA: SPENDER,
    counterpartyB: ZeroAddress,
    amountOrFlag: "1",
    callDataHash: `0x${"00".repeat(32)}`,
    nativeValueWei: "0",
    logIndex: 4
  };

  const binding =
    expectedEvidenceExecutionBinding(
      draft
    );

  draft.callDataHash =
    binding.callDataHash;
  draft.nativeValueWei =
    binding.nativeValueWei;
  draft.commitment =
    recomputeEvidenceCommitment(
      draft
    );
  draft.authorizationId =
    recomputeAuthorizationId(
      draft,
      11155111n,
      SOURCE
    );

  return draft;
}

function authorizationLog(
  address = SOURCE
) {
  const event =
    authorizationSourceInterface.getEvent(
      "AuthorizationPublished"
    );

  assert.ok(event);

  const encoded =
    authorizationSourceInterface.encodeEventLog(
      event,
      [
        AUTHORIZATION_ID,
        COMMITMENT,
        SENDER,
        9n,
        1n,
        7n,
        2_000_000_000n,
        2,
        TOKEN,
        TARGET_CODE_HASH,
        TOKEN,
        SPENDER,
        ZeroAddress,
        1n,
        CALL_DATA_HASH,
        0n
      ]
    );

  return {
    address,
    topics: encoded.topics,
    data: encoded.data,
    index: 4
  };
}

test(
  "AuthorizationPublished topic matches v3",
  () => {
    assert.equal(
      AUTHORIZATION_PUBLISHED_TOPIC,
      id(
        "AuthorizationPublished(bytes32,bytes32,address,uint256,uint256,uint256,uint64,uint8,address,bytes32,address,address,address,uint256,bytes32,uint256)"
      )
    );
  }
);

test(
  "preflight decodes one trusted source event",
  () => {
    const evidence =
      parseTrustedAuthorizationEvidence(
        [authorizationLog()],
        SOURCE
      );

    assert.equal(
      evidence.authorizationId,
      AUTHORIZATION_ID
    );
    assert.equal(
      evidence.commitment,
      COMMITMENT
    );
    assert.equal(
      evidence.sender,
      SENDER
    );
    assert.equal(
      evidence.executionNonce,
      "7"
    );
    assert.equal(
      evidence.validUntil,
      "2000000000"
    );
    assert.equal(
      evidence.targetCodeHash,
      TARGET_CODE_HASH
    );
    assert.equal(
      evidence.logIndex,
      4
    );
  }
);

test(
  "rejects event from untrusted emitter",
  () => {
    assert.throws(
      () =>
        parseTrustedAuthorizationEvidence(
          [
            authorizationLog(
              "0x6666666666666666666666666666666666666666"
            )
          ],
          SOURCE
        ),
      /found 0/
    );
  }
);

test(
  "rejects duplicate trusted auth events",
  () => {
    assert.throws(
      () =>
        parseTrustedAuthorizationEvidence(
          [
            authorizationLog(),
            authorizationLog()
          ],
          SOURCE
        ),
      /found 2/
    );
  }
);

test(
  "registry ABI includes trust constructor",
  () => {
    assert.equal(
      VERIFIED_AUTHORIZATION_REGISTRY_ABI[0],
      "constructor(uint64 sourceChainKey,uint256 sourceChainId,address authorizationSource)"
    );
  }
);

test(
  "registry ABI keeps B1 getter",
  () => {
    assert.ok(
      verifiedAuthorizationRegistryInterface.getFunction(
        "submitVerifiedAuthorization"
      )
    );

    const getter =
      verifiedAuthorizationRegistryInterface.getFunction(
        "getAuthorization"
      );

    assert.ok(getter);
    assert.equal(
      getter.outputs.length,
      6
    );
    assert.deepEqual(
      getter.outputs.map(
        output => output.type
      ),
      [
        "bytes32",
        "uint64",
        "uint64",
        "uint64",
        "uint64",
        "bool"
      ]
    );
  }
);

test(
  "linker patches only compiler-specified byte offsets",
  () => {
    const placeholder =
      "00".repeat(8) +
      "__".repeat(20) +
      "ff".repeat(8);

    const address =
      "0x1234567890123456789012345678901234567890";

    const linked =
      linkSolidityBytecode(
        placeholder,
        {
          "decoder.sol": {
            EvmV1Decoder: [
              {
                start: 8,
                length: 20
              }
            ]
          }
        },
        {
          EvmV1Decoder: address
        }
      );

    assert.equal(
      linked,
      `0x${"00".repeat(8)}${address.slice(2)}${"ff".repeat(8)}`
    );
  }
);

test(
  "linker rejects missing decoder address",
  () => {
    assert.throws(
      () =>
        linkSolidityBytecode(
          "00".repeat(40),
          {
            "decoder.sol": {
              EvmV1Decoder: [
                {
                  start: 4,
                  length: 20
                }
              ]
            }
          },
          {}
        ),
      /Missing deployment address/
    );
  }
);

test(
  "receipt success and trusted emitter are required",
  () => {
    const source =
      readFileSync(
        "contracts/VerifiedAuthorizationRegistry.sol",
        "utf8"
      );

    assert.match(
      source,
      /@gluwa\/asc-contracts\/contracts\/common\/EvmV1Decoder\.sol/
    );
    assert.match(
      source,
      /receipt\.receiptStatus\s*!=\s*1/
    );
    assert.match(
      source,
      /matchingLogs\[i\]\.address_\s*==\s*trustedAuthorizationSource/
    );
    assert.match(
      source,
      /TrustedAuthorizationEventCount/
    );
    assert.match(
      source,
      /EventCommitmentMismatch/
    );
    assert.match(
      source,
      /AuthorizationIdMismatch/
    );
  }
);

test(
  "registry reads semantics from the proven log",
  () => {
    const source =
      readFileSync(
        "contracts/VerifiedAuthorizationRegistry.sol",
        "utf8"
      );

    const signatureStart =
      source.indexOf(
        "function submitVerifiedAuthorization("
      );
    const signatureEnd =
      source.indexOf(
        ") external returns",
        signatureStart
      );

    assert.ok(signatureStart >= 0);
    assert.ok(signatureEnd > signatureStart);

    const signature =
      source.slice(
        signatureStart,
        signatureEnd
      );

    assert.doesNotMatch(
      signature,
      /authorizationId|commitment|actionCode|target|validUntil/
    );
  }
);

test(
  "registry ABI decodes custom errors",
  () => {
    const encoded =
      verifiedAuthorizationRegistryInterface.encodeErrorResult(
        "AuthorizationExpired",
        [2_000_000_000n, 2_000_000_001n]
      );

    const decoded =
      verifiedAuthorizationRegistryInterface.parseError(
        encoded
      );

    assert.ok(decoded);
    assert.equal(
      decoded.name,
      "AuthorizationExpired"
    );
  }
);

test(
  "known source evidence is accepted",
  () => {
    assert.doesNotThrow(
      () =>
        validateSourceAuthorizationEvidence(
          canonicalEvidence(),
          11155111n,
          SOURCE
        )
    );
  }
);

test(
  "rejects tampered emitted commitment",
  () => {
    const evidence =
      canonicalEvidence();

    evidence.commitment =
      `0x${"99".repeat(32)}`;

    assert.throws(
      () =>
        validateSourceAuthorizationEvidence(
          evidence,
          11155111n,
          SOURCE
        ),
      /commitment mismatch/
    );
  }
);

test(
  "tampered execution binding is rejected",
  () => {
    const evidence =
      canonicalEvidence();

    evidence.callDataHash =
      `0x${"88".repeat(32)}`;

    assert.throws(
      () =>
        validateSourceAuthorizationEvidence(
          evidence,
          11155111n,
          SOURCE
        ),
      /execution binding/
    );
  }
);

test(
  "authorization id includes source identity",
  () => {
    const evidence =
      canonicalEvidence();

    assert.throws(
      () =>
        validateSourceAuthorizationEvidence(
          evidence,
          1n,
          SOURCE
        ),
      /id mismatch/
    );

    assert.throws(
      () =>
        validateSourceAuthorizationEvidence(
          evidence,
          11155111n,
          "0x7777777777777777777777777777777777777777"
        ),
      /id mismatch/
    );
  }
);



test(
  "provenance view keeps the old getter",
  () => {
    const getter =
      verifiedAuthorizationRegistryInterface.getFunction(
        "getAuthorizationEvidence"
      );

    assert.ok(getter);
    assert.deepEqual(
      getter.outputs.map(output => output.type),
      [
        "bytes32",
        "uint64",
        "uint64",
        "uint64",
        "uint64",
        "address",
        "bytes32",
        "bytes32",
        "bool"
      ]
    );

    const source =
      readFileSync(
        "contracts/VerifiedAuthorizationRegistry.sol",
        "utf8"
      );

    assert.match(
      source,
      /provenTransactionHash\s*=\s*keccak256\(encodedTransaction\)/
    );
    assert.match(
      source,
      /sourceSender:\s*sourceSender/
    );
    assert.match(
      source,
      /transactionKey:\s*transactionKey/
    );
  }
);

test(
  "runtime compare ignores immutable slots",
  () => {
    const compiled =
      `0x${"aa".repeat(8)}${"00".repeat(4)}${"bb".repeat(8)}`;
    const deployed =
      `0x${"aa".repeat(8)}${"12".repeat(4)}${"bb".repeat(8)}`;

    const ranges = {
      "123": [
        {
          start: 8,
          length: 4
        }
      ]
    };

    assert.equal(
      maskSolidityByteRanges(
        compiled,
        ranges
      ),
      maskSolidityByteRanges(
        deployed,
        ranges
      )
    );

    const outsideMutation =
      `0x${"ab".repeat(8)}${"12".repeat(4)}${"bb".repeat(8)}`;

    assert.notEqual(
      maskSolidityByteRanges(
        compiled,
        ranges
      ),
      maskSolidityByteRanges(
        outsideMutation,
        ranges
      )
    );
  }
);


test(
  "accepts configured source anchors",
  () => {
    assert.doesNotThrow(
      () =>
        validateSemanticRegistryTrustAnchors(
          {
            trustedSourceChainKey: 1,
            trustedSourceChainId: 11155111,
            trustedAuthorizationSource: SOURCE,
            authorizationCommitmentDomain:
              AUTHORIZATION_COMMITMENT_DOMAIN,
            authorizationIdDomain:
              AUTHORIZATION_ID_DOMAIN
          },
          {
            sourceChainKey: 1,
            sourceChainId: 11155111,
            authorizationSource: SOURCE
          }
        )
    );
  }
);

test(
  "rejects wrong source key or source address",
  () => {
    assert.throws(
      () =>
        validateSemanticRegistryTrustAnchors(
          {
            trustedSourceChainKey: 2,
            trustedSourceChainId: 11155111,
            trustedAuthorizationSource: SOURCE,
            authorizationCommitmentDomain:
              AUTHORIZATION_COMMITMENT_DOMAIN,
            authorizationIdDomain:
              AUTHORIZATION_ID_DOMAIN
          },
          {
            sourceChainKey: 1,
            sourceChainId: 11155111,
            authorizationSource: SOURCE
          }
        ),
      /chainKey 2.*expected 1/
    );

    assert.throws(
      () =>
        validateSemanticRegistryTrustAnchors(
          {
            trustedSourceChainKey: 1,
            trustedSourceChainId: 11155111,
            trustedAuthorizationSource:
              "0x7777777777777777777777777777777777777777",
            authorizationCommitmentDomain:
              AUTHORIZATION_COMMITMENT_DOMAIN,
            authorizationIdDomain:
              AUTHORIZATION_ID_DOMAIN
          },
          {
            sourceChainKey: 1,
            sourceChainId: 11155111,
            authorizationSource: SOURCE
          }
        ),
      /registry source mismatch/
    );
  }
);

test(
  "semantic trust-anchor validator rejects domain drift",
  () => {
    assert.throws(
      () =>
        validateSemanticRegistryTrustAnchors(
          {
            trustedSourceChainKey: 1,
            trustedSourceChainId: 11155111,
            trustedAuthorizationSource: SOURCE,
            authorizationCommitmentDomain:
              `0x${"99".repeat(32)}`,
            authorizationIdDomain:
              AUTHORIZATION_ID_DOMAIN
          },
          {
            sourceChainKey: 1,
            sourceChainId: 11155111,
            authorizationSource: SOURCE
          }
        ),
      /commitment domain mismatch/
    );
  }
);
