import assert from "node:assert/strict";
import test from "node:test";

import {
  mkdtempSync,
  readFileSync
} from "node:fs";

import {
  tmpdir
} from "node:os";

import {
  join
} from "node:path";

import {
  LIVE_DEPLOYMENT_ARTIFACT_VERSION,
  loadLiveDeploymentArtifact,
  recordSemanticRegistryDeployment,
  recordSourceDeployment,
  resolveLiveDeploymentConfig
} from "./live-deployment.js";

const SOURCE_A =
  "0x1111111111111111111111111111111111111111";
const SOURCE_B =
  "0x2222222222222222222222222222222222222222";
const REGISTRY =
  "0x3333333333333333333333333333333333333333";
const HASH =
  `0x${"44".repeat(32)}`;

function tempArtifactPath(): string {
  return join(
    mkdtempSync(
      join(tmpdir(), "agentfirewall-live-deployment-")
    ),
    "build",
    "live-deployment.json"
  );
}

test(
  "deployment artifact stores source and registry",
  () => {
    const path = tempArtifactPath();

    recordSourceDeployment(
      {
        network: "sepolia",
        chainId: "11155111",
        address: SOURCE_A,
        runtimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    recordSemanticRegistryDeployment(
      {
        network: "creditcoin-testnet",
        chainId: "102031",
        sourceChainKey: "1",
        sourceChainId: "11155111",
        trustedAuthorizationSource: SOURCE_A,
        decoderMode: "inlined",
        evmV1Decoder: null,
        evmV1DecoderRuntimeCodeHash: null,
        decoderDeploymentTx: null,
        address: REGISTRY,
        runtimeCodeHash: HASH,
        normalizedRuntimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    const loaded =
      loadLiveDeploymentArtifact(path);

    assert.ok(loaded);
    assert.equal(
      loaded.version,
      LIVE_DEPLOYMENT_ARTIFACT_VERSION
    );
    assert.equal(
      loaded.source?.address,
      SOURCE_A
    );
    assert.equal(
      loaded.semanticRegistry?.address,
      REGISTRY
    );

    const raw =
      readFileSync(path, "utf8");

    assert.doesNotMatch(
      raw,
      /private.?key|mnemonic|secret/i
    );
  }
);

test(
  "new source invalidates old registry record",
  () => {
    const path = tempArtifactPath();

    recordSourceDeployment(
      {
        network: "sepolia",
        chainId: "11155111",
        address: SOURCE_A,
        runtimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    recordSemanticRegistryDeployment(
      {
        network: "creditcoin-testnet",
        chainId: "102031",
        sourceChainKey: "1",
        sourceChainId: "11155111",
        trustedAuthorizationSource: SOURCE_A,
        decoderMode: "inlined",
        evmV1Decoder: null,
        evmV1DecoderRuntimeCodeHash: null,
        decoderDeploymentTx: null,
        address: REGISTRY,
        runtimeCodeHash: HASH,
        normalizedRuntimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    recordSourceDeployment(
      {
        network: "sepolia",
        chainId: "11155111",
        address: SOURCE_B,
        runtimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    const loaded =
      loadLiveDeploymentArtifact(path);

    assert.ok(loaded);
    assert.equal(
      loaded.source?.address,
      SOURCE_B
    );
    assert.equal(
      loaded.semanticRegistry,
      undefined
    );
  }
);

test(
  "deployment config can use recorded values",
  () => {
    const path = tempArtifactPath();

    recordSourceDeployment(
      {
        network: "sepolia",
        chainId: "11155111",
        address: SOURCE_A,
        runtimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    recordSemanticRegistryDeployment(
      {
        network: "creditcoin-testnet",
        chainId: "102031",
        sourceChainKey: "1",
        sourceChainId: "11155111",
        trustedAuthorizationSource: SOURCE_A,
        decoderMode: "inlined",
        evmV1Decoder: null,
        evmV1DecoderRuntimeCodeHash: null,
        decoderDeploymentTx: null,
        address: REGISTRY,
        runtimeCodeHash: HASH,
        normalizedRuntimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    const config =
      resolveLiveDeploymentConfig(
        {},
        path
      );

    assert.deepEqual(
      config,
      {
        sourceChainKey: "1",
        authorizationSource: SOURCE_A,
        authorizationSourceRuntimeCodeHash: HASH,
        registryAddress: REGISTRY,
        registryRuntimeCodeHash: HASH
      }
    );
  }
);

test(
  "env overrides cannot change recorded trust anchors",
  () => {
    const path = tempArtifactPath();

    recordSourceDeployment(
      {
        network: "sepolia",
        chainId: "11155111",
        address: SOURCE_A,
        runtimeCodeHash: HASH,
        deploymentTx: HASH
      },
      path
    );

    assert.throws(
      () =>
        resolveLiveDeploymentConfig(
          {
            AUTHORIZATION_SOURCE_ADDRESS:
              SOURCE_B
          },
          path
        ),
      /conflicts with live deployment artifact/
    );
  }
);
