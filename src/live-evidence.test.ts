import assert from "node:assert/strict";
import test from "node:test";

import type {
  LiveAuthorizationArtifact
} from "./live-demo.js";

import {
  LIVE_EVIDENCE_VERSION,
  buildLiveJudgeEvidence,
  historicalEvidenceMatchesArtifacts
} from "./live-evidence.js";

const HASH_A =
  `0x${"aa".repeat(32)}`;
const HASH_B =
  `0x${"bb".repeat(32)}`;
const SOURCE =
  "0x1111111111111111111111111111111111111111";
const REGISTRY =
  "0x2222222222222222222222222222222222222222";
const SENDER =
  "0x3333333333333333333333333333333333333333";
const RECIPIENT =
  "0x4444444444444444444444444444444444444444";

function canonicalArtifact(): LiveAuthorizationArtifact {
  return {
    version: "AgentFirewall.LiveAuthorization.v1",
    createdAt: "2026-09-10T00:00:00.000Z",
    build: {
      sourceCommit:
        "0123456789abcdef0123456789abcdef01234567",
      sourceTreeClean: true
    },
    source: {
      network: "sepolia",
      chainId: "11155111",
      authorizationSource: SOURCE,
      transactionHash: HASH_A,
      blockNumber: "123",
      authorizationId: HASH_B,
      commitment: HASH_A,
      sourceAuthorizationNonce: "7",
      transactionIndex: "5"
    },
    execution: {
      declaredIntent: {
        executionChainId: "11155111",
        sender: SENDER,
        executionNonce: "8",
        validUntil: "2000000000",
        targetCodeHash: HASH_A,
        action: "native_transfer",
        target: RECIPIENT,
        asset: {
          kind: "native"
        },
        recipient: RECIPIENT,
        amountRaw: "1",
        method: "native_transfer"
      },
      transaction: {
        chain: "sepolia",
        from: SENDER,
        to: RECIPIENT,
        nonce: "8",
        data: "0x",
        valueWei: "1"
      },
      mutatedTransaction: {
        chain: "sepolia",
        from: SENDER,
        to: SOURCE,
        nonce: "8",
        data: "0x",
        valueWei: "1"
      }
    },
    creditcoin: {
      registryAddress: REGISTRY,
      transactionHash: HASH_B,
      blockNumber: "456",
      sourceChainKey: "1",
      sourceBlockNumber: "123",
      transactionIndex: "5",
      transactionKey: HASH_A,
      provenTransactionHash: HASH_B,
      proofPreflightVerified: true
    },
    verification: {
      generatedAt: "2026-09-10T00:10:00.000Z",
      mutated: {
        simulationOk: true,
        decision: "BLOCK",
        criticalFindingCodes: [
          "AUTHORIZATION_COMMITMENT_MISMATCH"
        ],
        signerCallCount: 0
      },
      exact: {
        simulationOk: true,
        decision: "ALLOW",
        criticalFindingCodes: [],
        signerCallCount: 1
      }
    },
    controllerApproval: {
      generatedAt: "2026-09-10T00:11:00.000Z",
      controller: SOURCE,
      executor: SENDER,
      signature: `0x${"11".repeat(65)}`,
      message: {
        authorizationId: HASH_B,
        commitment: HASH_A,
        executor: SENDER,
        executionChainId: "11155111",
        executionNonce: "8",
        validUntil: "2000000000",
        registryAddress: REGISTRY,
        sourceChainKey: "1"
      }
    },
    executionResult: {
      transactionHash: `0x${"cc".repeat(32)}`,
      blockNumber: "789",
      controller: SOURCE,
      executor: SENDER,
      signerCallCount: 1
    }
  };
}

test(
  "evidence links publish, ingest and send result",
  () => {
    const evidence =
      buildLiveJudgeEvidence(
        canonicalArtifact()
      );

    assert.equal(
      evidence.version,
      LIVE_EVIDENCE_VERSION
    );
    assert.equal(
      evidence.firewall.mutatedExecutablePayload.simulation,
      "SUCCESS"
    );
    assert.equal(
      evidence.firewall.mutatedExecutablePayload.decision,
      "BLOCK"
    );
    assert.equal(
      evidence.firewall.exactProofBackedPayload.decision,
      "ALLOW"
    );
    assert.match(
      evidence.source.explorerTransaction,
      /sepolia\.etherscan\.io\/tx\//
    );
    assert.match(
      evidence.creditcoin.explorerTransaction,
      /creditcoin-testnet\.blockscout\.com\/tx\//
    );
    assert.equal(
      evidence.build?.sourceCommit,
      "0123456789abcdef0123456789abcdef01234567"
    );
    assert.equal(
      evidence.controllerApproval?.authoritySeparated,
      true
    );
    assert.equal(
      evidence.guardedSigner?.mutated.signerCallCount,
      0
    );
    assert.equal(
      evidence.guardedSigner?.canonical.signerCallCount,
      1
    );
    assert.equal(
      evidence.transactions?.execution,
      `0x${"cc".repeat(32)}`
    );
  }
);

test(
  "evidence rejects tx-index mismatch",
  () => {
    const artifact =
      canonicalArtifact();

    if (!artifact.creditcoin) {
      throw new Error("test setup failed");
    }

    artifact.creditcoin.transactionIndex =
      "6";

    assert.throws(
      () =>
        buildLiveJudgeEvidence(
          artifact
        ),
      /transaction index 6.*receipt index 5/
    );
  }
);

test(
  "BLOCK/ALLOW evidence must match the recorded run",
  () => {
    const artifact =
      canonicalArtifact();

    if (!artifact.verification) {
      throw new Error("test setup failed");
    }

    artifact.verification.mutated.simulationOk =
      false;

    assert.throws(
      () =>
        buildLiveJudgeEvidence(
          artifact
        ),
      /requires mutated payload simulation SUCCESS and firewall BLOCK/
    );
  }
);


test(
  "evidence files agree with each other",
  () => {
    const artifact =
      canonicalArtifact();
    const evidence =
      buildLiveJudgeEvidence(artifact);

    const input = {
      deployment: {
        source: {
          chainId: "11155111",
          address: SOURCE
        },
        semanticRegistry: {
          sourceChainKey: "1",
          sourceChainId: "11155111",
          trustedAuthorizationSource: SOURCE,
          address: REGISTRY
        }
      },
      artifact,
      evidence,
      registryRecord: {
        commitment: HASH_A,
        sourceChainKey: "1",
        sourceBlockNumber: "123",
        transactionIndex: "5",
        validUntil: "2000000000",
        verified: true
      }
    };

    assert.equal(
      historicalEvidenceMatchesArtifacts(input),
      true
    );

    assert.equal(
      historicalEvidenceMatchesArtifacts({
        ...input,
        deployment: null
      }),
      false
    );

    assert.equal(
      historicalEvidenceMatchesArtifacts({
        ...input,
        evidence: {
          ...evidence,
          creditcoin: {
            ...evidence.creditcoin,
            registryAddress: SOURCE
          }
        }
      }),
      false
    );

    assert.equal(
      historicalEvidenceMatchesArtifacts({
        ...input,
        evidence: {
          ...evidence,
          firewall: {
            ...evidence.firewall,
            mutatedExecutablePayload: {
              ...evidence.firewall.mutatedExecutablePayload,
              criticalFindingCodes: ["DIFFERENT_FINDING"]
            }
          }
        }
      }),
      false
    );

    assert.ok(evidence.execution);
    assert.equal(
      historicalEvidenceMatchesArtifacts({
        ...input,
        evidence: {
          ...evidence,
          execution: {
            ...evidence.execution,
            transactionHash: HASH_A
          }
        }
      }),
      false
    );
  }
);
