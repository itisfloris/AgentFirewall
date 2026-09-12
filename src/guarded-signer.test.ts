import assert from "node:assert/strict";
import test from "node:test";

import {
  Transaction,
  Wallet,
  keccak256,
  type HDNodeWallet,
  type Provider,
  type Signer,
  type TransactionRequest,
  type TransactionResponse
} from "ethers";

import {
  commitmentFromDeclaredIntent
} from "./authorization.js";

import {
  controllerApprovalTypedDataV2
} from "./controller-approval.js";

import {
  GuardedSigner,
  GuardedSignerRejectedError,
  enforceFeeSafety
} from "./guarded-signer.js";

import type {
  DeclaredIntent
} from "./intent.js";

import type {
  VerifiedAuthorizationReader
} from "./verified-preflight.js";

const AUTHORIZATION_ID =
  `0x${"ab".repeat(32)}`;
const REGISTRY =
  "0x7777777777777777777777777777777777777777";
const RECIPIENT =
  "0x1111111111111111111111111111111111111111";
const ATTACKER =
  "0x9999999999999999999999999999999999999999";
const EMPTY_CODE_HASH =
  keccak256("0x");
const VALID_UNTIL =
  "2000000000";

const feePolicy = {
  maxGasLimit: "50000",
  maxFeePerGasWei: "100",
  maxPriorityFeePerGasWei: "10",
  maxTotalFeeWei: "5000000"
};

function declaredIntent(
  sender: string
): DeclaredIntent {
  return {
    executionChainId: "1",
    sender,
    executionNonce: "7",
    validUntil: VALID_UNTIL,
    targetCodeHash: EMPTY_CODE_HASH,
    action: "native_transfer",
    target: RECIPIENT,
    asset: {
      kind: "native"
    },
    recipient: RECIPIENT,
    amountRaw: "1",
    method: "native_transfer"
  };
}

function readerFor(
  intent: DeclaredIntent
): VerifiedAuthorizationReader {
  const commitment =
    commitmentFromDeclaredIntent(intent);

  return {
    async getAuthorization(authorizationId) {
      return {
        authorizationId,
        commitment,
        verified: true,
        sourceChainKey: "1",
        sourceBlockNumber: "123",
        transactionIndex: "4",
        validUntil: VALID_UNTIL,
        registryAddress: REGISTRY,
        creditcoinChainId: "102031",
        rpcSource: "test-double",
        registryTrustAnchorsVerified: true,
        registryRuntimeCodeHashVerified: true
      };
    }
  };
}

function fakeProvider(
  onPinnedCall?: () => void,
  blockHashForCall?: (call: number) => string,
  broadcastHashOverride?: string
) {
  let broadcastRaw: string | null = null;
  let blockReads = 0;

  const provider = {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getTransactionCount() {
      return 7;
    },
    async getBlock() {
      blockReads += 1;
      return {
        number: 123,
        hash: blockHashForCall?.(blockReads) ??
          `0x${"12".repeat(32)}`,
        timestamp: 1900000000
      };
    },
    async estimateGas() {
      return 21000n;
    },
    async send(method: string) {
      switch (method) {
        case "eth_getCode":
          return "0x";
        case "eth_getBalance":
          return "0x0";
        case "eth_call":
          onPinnedCall?.();
          return "0x";
        default:
          throw new Error(`Unexpected RPC method ${method}`);
      }
    },
    async broadcastTransaction(raw: string) {
      broadcastRaw = raw;
      return {
        hash: broadcastHashOverride ??
          Transaction.from(raw).hash ??
          `0x${"34".repeat(32)}`
      } as TransactionResponse;
    }
  } as unknown as Provider & {
    send(method: string, params: Array<unknown>): Promise<unknown>;
  };

  return {
    provider,
    getBroadcastRaw: () => broadcastRaw,
    getBlockReads: () => blockReads
  };
}

function fakeSigner(
  wallet: HDNodeWallet,
  provider: Provider,
  counters: {
    signCalls: number;
  }
): Signer {
  return {
    provider,
    async getAddress() {
      return wallet.address;
    },
    async populateTransaction(
      request: TransactionRequest
    ) {
      return {
        ...request,
        type: 2,
        gasLimit: 21000n,
        maxFeePerGas: 2n,
        maxPriorityFeePerGas: 1n
      };
    },
    async signTransaction(
      request: TransactionRequest
    ) {
      counters.signCalls += 1;
      return wallet.signTransaction(request);
    }
  } as unknown as Signer;
}

async function controllerSignature(
  controller: HDNodeWallet,
  intent: DeclaredIntent
): Promise<string> {
  const commitment =
    commitmentFromDeclaredIntent(intent);

  const typed = controllerApprovalTypedDataV2({
    authorizationId: AUTHORIZATION_ID,
    commitment,
    executor: intent.sender ?? "",
    executionChainId: intent.executionChainId,
    executionNonce: intent.executionNonce ?? "",
    validUntil: intent.validUntil ?? "",
    registryAddress: REGISTRY,
    sourceChainKey: "1"
  }, feePolicy);

  return controller.signTypedData(
    typed.domain,
    typed.types,
    typed.message
  );
}

test(
  "caller mutation does not change the tx being signed",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const requested = {
      to: RECIPIENT,
      data: "0x",
      valueWei: "1"
    };

    const fake = fakeProvider(() => {
      requested.to = ATTACKER;
    });
    const counters = { signCalls: 0 };
    const signer = fakeSigner(
      wallet,
      fake.provider,
      counters
    );
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController:
          controller.address,
        feePolicy
      }
    );

    const signature =
      await controllerSignature(
        controller,
        intent
      );

    const result =
      await guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        requested,
        signature,
        { maxNativeValueWei: "1" }
      );

    assert.equal(counters.signCalls, 1);
    assert.equal(requested.to, ATTACKER);
    assert.equal(result.verdict.decision, "ALLOW");

    const raw = fake.getBroadcastRaw();
    assert.ok(raw);
    const signed = Transaction.from(raw);
    assert.equal(signed.to, RECIPIENT);
    assert.equal(signed.value, 1n);
    assert.equal(signed.nonce, 7);
  }
);

test(
  "BLOCK path does not call the signer",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(
      wallet,
      fake.provider,
      counters
    );
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController:
          controller.address,
        feePolicy
      }
    );
    const signature =
      await controllerSignature(
        controller,
        intent
      );

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        {
          to: ATTACKER,
          data: "0x",
          valueWei: "1"
        },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "VERIFIED_PREFLIGHT_BLOCKED"
    );

    assert.equal(counters.signCalls, 0);
  }
);

test(
  "fee ceilings are enforced",
  () => {
    assert.throws(
      () =>
        enforceFeeSafety(
          {
            type: 2,
            gasLimit: 21000n,
            maxFeePerGas: 101n,
            maxPriorityFeePerGas: 1n
          },
          feePolicy
        ),
      /maxFeePerGas/
    );

    assert.throws(
      () =>
        enforceFeeSafety(
          {
            type: 2,
            gasLimit: 50000n,
            maxFeePerGas: 100n,
            maxPriorityFeePerGas: 10n
          },
          {
            ...feePolicy,
            maxTotalFeeWei: "4999999"
          }
        ),
      /Worst-case fee/
    );
  }
);

test(
  "executor cannot approve itself",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(
      wallet,
      fake.provider,
      counters
    );
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );

    const forgedByExecutor =
      await controllerSignature(
        wallet,
        intent
      );

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        {
          to: RECIPIENT,
          data: "0x",
          valueWei: "1"
        },
        forgedByExecutor,
        { maxNativeValueWei: "1" }
      ),
      /does not match trusted controller/
    );

    assert.equal(counters.signCalls, 0);
  }
);

test(
  "controller and executor must differ",
  async () => {
    const wallet = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: wallet.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(wallet, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "AUTHORITY_SEPARATION_REQUIRED"
    );

    assert.equal(counters.signCalls, 0);
  }
);

test(
  "fee policy is copied on construction",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const mutableFeePolicy = {
      ...feePolicy,
      maxFeePerGasWei: "1",
      maxPriorityFeePerGasWei: "1"
    };

    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy: mutableFeePolicy
      }
    );

    mutableFeePolicy.maxFeePerGasWei = "1000000";

    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "MAX_FEE_PER_GAS_EXCEEDED"
    );

    assert.equal(counters.signCalls, 0);
  }
);

test(
  "provider errors do not leak RPC credentials",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const secretUrl =
      "https://alice:password@host.example/v2/SECRET?key=SECRET2";

    const provider = {
      async getNetwork() {
        throw new Error(`request to ${secretUrl} failed`);
      },
      async send() {
        throw new Error("unexpected send");
      }
    } as unknown as Provider & {
      send(method: string, params: Array<unknown>): Promise<unknown>;
    };

    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );

    const signature = await controllerSignature(controller, intent);

    try {
      await guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature
      );
      assert.fail("expected GuardedSigner to reject provider failure");
    } catch (error) {
      assert.ok(error instanceof GuardedSignerRejectedError);
      assert.equal(error.code, "GUARDED_SIGNER_DEPENDENCY_FAILED");
      assert.equal(error.message.includes("password"), false);
      assert.equal(error.message.includes("SECRET"), false);
      assert.match(error.message, /https:\/\/host\.example/);
    }

    assert.equal(counters.signCalls, 0);
  }
);


test(
  "rejects signer output for a different tx",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };

    const signer = {
      ...fakeSigner(wallet, fake.provider, counters),
      provider: fake.provider,
      async getAddress() {
        return wallet.address;
      },
      async populateTransaction(request: TransactionRequest) {
        return {
          ...request,
          type: 2,
          gasLimit: 21000n,
          maxFeePerGas: 2n,
          maxPriorityFeePerGas: 1n
        };
      },
      async signTransaction(request: TransactionRequest) {
        counters.signCalls += 1;
        return wallet.signTransaction({
          ...request,
          to: ATTACKER
        });
      }
    } as unknown as Signer;

    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "SIGNED_TRANSACTION_MISMATCH"
    );

    assert.equal(counters.signCalls, 1);
    assert.equal(fake.getBroadcastRaw(), null);
  }
);

test(
  "rejects a changed pre-sign block",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const stableHash = `0x${"12".repeat(32)}`;
    const reorgedHash = `0x${"34".repeat(32)}`;
    const fake = fakeProvider(
      undefined,
      (call) => call === 4 ? reorgedHash : stableHash
    );
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "PRESIGN_BLOCK_CHANGED"
    );

    assert.equal(fake.getBlockReads(), 4);
    assert.equal(counters.signCalls, 0);
    assert.equal(fake.getBroadcastRaw(), null);
  }
);

test(
  "rejects oversized calldata",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      { trustedController: controller.address, feePolicy }
    );
    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        {
          to: RECIPIENT,
          data: `0x${"00".repeat(65537)}`,
          valueWei: "1"
        },
        signature
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "TRANSACTION_DATA_TOO_LARGE"
    );

    assert.equal(counters.signCalls, 0);
    assert.equal(fake.getBlockReads(), 0);
  }
);

test(
  "rejects bad controller signature",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      { trustedController: controller.address, feePolicy }
    );

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        "0x1234"
      ),
      /Controller approval must be a 64-byte compact or 65-byte ECDSA signature/
    );

    assert.equal(counters.signCalls, 0);
  }
);


test(
  "rejects a wrong broadcast hash",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider(
      undefined,
      undefined,
      `0x${"ef".repeat(32)}`
    );
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        { to: RECIPIENT, data: "0x", valueWei: "1" },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "BROADCAST_HASH_MISMATCH"
    );

    assert.equal(counters.signCalls, 1);
    assert.ok(fake.getBroadcastRaw());
  }
);


test(
  "negative fee fields are rejected",
  () => {
    assert.throws(
      () =>
        enforceFeeSafety(
          {
            type: 2,
            gasLimit: 21000n,
            maxFeePerGas: -1n,
            maxPriorityFeePerGas: 0n
          },
          feePolicy
        ),
      /non-negative/
    );

    assert.throws(
      () =>
        enforceFeeSafety(
          {
            type: 0,
            gasLimit: 21000n,
            gasPrice: -1n
          },
          feePolicy
        ),
      /non-negative/
    );
  }
);


test(
  "extra request fields are ignored",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signer = fakeSigner(wallet, fake.provider, counters);
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);

    const result = await guarded.guardAndSendVerified(
      AUTHORIZATION_ID,
      intent,
      {
        to: RECIPIENT,
        data: "0x",
        valueWei: "1",
        nonce: "999",
        chainId: "31337"
      } as unknown as Parameters<GuardedSigner["guardAndSendVerified"]>[2],
      signature
    );

    assert.equal(result.transaction.nonce, 7);
    assert.equal(result.transaction.chainId, 1n);
    assert.equal(counters.signCalls, 1);
    assert.ok(fake.getBroadcastRaw());
  }
);

test(
  "concurrent sends cannot reserve the same sender chain nonce twice",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    let releaseReader: (() => void) | undefined;
    let readerEntered: (() => void) | undefined;
    const entered = new Promise<void>(resolve => {
      readerEntered = resolve;
    });
    const hold = new Promise<void>(resolve => {
      releaseReader = resolve;
    });
    const baseReader = readerFor(intent);
    const delayedReader: VerifiedAuthorizationReader = {
      async getAuthorization(id) {
        readerEntered?.();
        await hold;
        return baseReader.getAuthorization(id);
      }
    };
    const guarded = new GuardedSigner(
      fakeSigner(wallet, fake.provider, counters),
      delayedReader,
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);
    const candidate = {
      to: RECIPIENT,
      data: "0x",
      valueWei: "1"
    };

    const first = guarded.guardAndSendVerified(
      AUTHORIZATION_ID,
      intent,
      candidate,
      signature,
      { maxNativeValueWei: "1" }
    );

    await entered;

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        candidate,
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "NONCE_ALREADY_RESERVED"
    );

    releaseReader?.();
    const result = await first;
    assert.equal(result.verdict.decision, "ALLOW");
    assert.equal(counters.signCalls, 1);
  }
);

test(
  "nonce reservation is released after a signing failure",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    let failNextSign = true;
    const base = fakeSigner(wallet, fake.provider, counters);
    const signer = {
      ...base,
      provider: fake.provider,
      async signTransaction(request: TransactionRequest) {
        counters.signCalls += 1;
        if (failNextSign) {
          failNextSign = false;
          throw new Error("instrumented signing failure");
        }
        return wallet.signTransaction(request);
      }
    } as unknown as Signer;
    const guarded = new GuardedSigner(
      signer,
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy
      }
    );
    const signature = await controllerSignature(controller, intent);
    const candidate = {
      to: RECIPIENT,
      data: "0x",
      valueWei: "1"
    };

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        candidate,
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "GUARDED_SIGNER_DEPENDENCY_FAILED"
    );

    const result = await guarded.guardAndSendVerified(
      AUTHORIZATION_ID,
      intent,
      candidate,
      signature,
      { maxNativeValueWei: "1" }
    );

    assert.equal(result.verdict.decision, "ALLOW");
    assert.equal(counters.signCalls, 2);
  }
);

test(
  "controller approval v2 binds fee ceilings",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const fake = fakeProvider();
    const counters = { signCalls: 0 };
    const signature = await controllerSignature(controller, intent);
    const guarded = new GuardedSigner(
      fakeSigner(wallet, fake.provider, counters),
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy: {
          ...feePolicy,
          maxFeePerGasWei: "99"
        }
      }
    );

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        {
          to: RECIPIENT,
          data: "0x",
          valueWei: "1"
        },
        signature,
        { maxNativeValueWei: "1" }
      ),
      /does not match trusted controller/
    );

    assert.equal(counters.signCalls, 0);
  }
);

test(
  "secondary execution RPC disagreement blocks before signing",
  async () => {
    const wallet = Wallet.createRandom();
    const controller = Wallet.createRandom();
    const intent = declaredIntent(wallet.address);
    const primary = fakeProvider();
    const secondary = fakeProvider(
      undefined,
      () => `0x${"34".repeat(32)}`
    );
    const counters = { signCalls: 0 };
    const guarded = new GuardedSigner(
      fakeSigner(wallet, primary.provider, counters),
      readerFor(intent),
      {
        trustedController: controller.address,
        feePolicy,
        secondaryExecutionProvider: secondary.provider
      }
    );
    const signature = await controllerSignature(controller, intent);

    await assert.rejects(
      guarded.guardAndSendVerified(
        AUTHORIZATION_ID,
        intent,
        {
          to: RECIPIENT,
          data: "0x",
          valueWei: "1"
        },
        signature,
        { maxNativeValueWei: "1" }
      ),
      (error: unknown) =>
        error instanceof GuardedSignerRejectedError &&
        error.code === "SECONDARY_RPC_MISMATCH"
    );

    assert.equal(counters.signCalls, 0);
  }
);
