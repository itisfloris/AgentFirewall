import {
  Transaction,
  Wallet,
  keccak256,
  randomBytes,
  type Provider,
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
  GuardedSignerRejectedError
} from "./guarded-signer.js";

import type {
  DeclaredIntent
} from "./intent.js";

import type {
  TransactionSignerBoundary
} from "./signer-boundary.js";

import type {
  VerifiedAuthorizationReader
} from "./verified-preflight.js";

const EMPTY_CODE_HASH = keccak256("0x");
const REGISTRY = "0x7777777777777777777777777777777777777777";
const VALID_UNTIL = "2000000000";

const feePolicy = {
  maxGasLimit: "50000",
  maxFeePerGasWei: "100",
  maxPriorityFeePerGasWei: "10",
  maxTotalFeeWei: "5000000"
};

function runtimeProvider() {
  let broadcastRaw: string | null = null;

  const provider = {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getTransactionCount() {
      return 7;
    },
    async getBlock() {
      return {
        number: 123,
        hash: `0x${"12".repeat(32)}`,
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
          return "0x";
        default:
          throw new Error(`Unexpected RPC method ${method}`);
      }
    },
    async broadcastTransaction(raw: string) {
      broadcastRaw = raw;
      return {
        hash: Transaction.from(raw).hash
      } as TransactionResponse;
    }
  } as unknown as Provider & {
    send(method: string, params: Array<unknown>): Promise<unknown>;
  };

  return {
    provider,
    getBroadcastRaw: () => broadcastRaw
  };
}

function runtimeSigner(
  wallet: ReturnType<typeof Wallet.createRandom>,
  provider: Provider,
  counters: { signCalls: number }
): TransactionSignerBoundary {
  return {
    provider,
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
      return wallet.signTransaction(request);
    }
  };
}

function authorizationReader(
  authorizationId: string,
  intent: DeclaredIntent
): VerifiedAuthorizationReader {
  const commitment = commitmentFromDeclaredIntent(intent);

  return {
    async getAuthorization(requestedId) {
      if (requestedId.toLowerCase() !== authorizationId.toLowerCase()) {
        return null;
      }

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
        rpcSource: "runtime-judge-instrumented-reader",
        registryTrustAnchorsVerified: true,
        registryRuntimeCodeHashVerified: true
      };
    }
  };
}

async function signControllerApproval(
  controller: ReturnType<typeof Wallet.createRandom>,
  authorizationId: string,
  intent: DeclaredIntent
): Promise<string> {
  const typed = controllerApprovalTypedDataV2({
    authorizationId,
    commitment: commitmentFromDeclaredIntent(intent),
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

async function runScenario(
  kind: "mutated" | "canonical"
) {
  const executor = Wallet.createRandom();
  const controller = Wallet.createRandom();
  const recipient = Wallet.createRandom().address;
  const attacker = Wallet.createRandom().address;
  const authorizationId = keccak256(randomBytes(32));
  const intent: DeclaredIntent = {
    executionChainId: "1",
    sender: executor.address,
    executionNonce: "7",
    validUntil: VALID_UNTIL,
    targetCodeHash: EMPTY_CODE_HASH,
    action: "native_transfer",
    target: recipient,
    asset: { kind: "native" },
    recipient,
    amountRaw: "1",
    method: "native_transfer"
  };

  const fake = runtimeProvider();
  const counters = { signCalls: 0 };
  const guarded = new GuardedSigner(
    runtimeSigner(executor, fake.provider, counters),
    authorizationReader(authorizationId, intent),
    {
      trustedController: controller.address,
      feePolicy,
      rpcSourceLabel: "runtime-judge-instrumented-provider"
    }
  );
  const signature = await signControllerApproval(
    controller,
    authorizationId,
    intent
  );
  const candidate = {
    to: kind === "canonical" ? recipient : attacker,
    data: "0x",
    valueWei: "1"
  };

  try {
    const result = await guarded.guardAndSendVerified(
      authorizationId,
      intent,
      candidate,
      signature,
      { maxNativeValueWei: "1" }
    );

    return {
      simulation: result.verdict.onchain.simulation.ok ? "SUCCESS" : "FAILURE",
      decision: result.verdict.decision,
      signTransactionCalls: counters.signCalls,
      transactionHash: result.transactionHash,
      rawBroadcastObserved: Boolean(fake.getBroadcastRaw())
    };
  } catch (error) {
    if (
      error instanceof GuardedSignerRejectedError &&
      error.verdict
    ) {
      return {
        simulation: error.verdict.onchain.simulation.ok ? "SUCCESS" : "FAILURE",
        decision: error.verdict.decision,
        signTransactionCalls: counters.signCalls,
        rawBroadcastObserved: Boolean(fake.getBroadcastRaw())
      };
    }

    throw error;
  }
}

const result = {
  version: "AgentFirewall.RuntimeJudge.v1",
  proofKind: "runtime-current-guarded-signer",
  mutated: await runScenario("mutated"),
  canonical: await runScenario("canonical")
};

console.log(`JUDGE_RUNTIME_RESULT ${JSON.stringify(result)}`);
