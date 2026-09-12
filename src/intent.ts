import {
  Interface,
  getAddress,
  isAddress
} from "ethers";

import { z } from "zod";

import {
  resolveNetwork
} from "./networks.js";

import type {
  TransactionInput
} from "./analyzer.js";

const unsignedInteger =
  z.string()
    .max(78)
    .regex(/^\d+$/);

const addressString =
  z.string().max(128).refine(
    isAddress,
    "Invalid EVM address"
  );

const commonIntentFields = {
  executionChainId:
    unsignedInteger,

  sender:
    addressString.optional(),

  executionNonce:
    unsignedInteger.optional(),

  validUntil:
    unsignedInteger.optional(),

  targetCodeHash:
    z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),

  target:
    addressString,

  method:
    z.string().min(1).max(128).optional()
};

export const declaredIntentSchema =
  z.discriminatedUnion(
    "action",
    [
      z.object({
        ...commonIntentFields,
        action:
          z.literal("native_transfer"),
        asset:
          z.object({
            kind:
              z.literal("native")
          }).strict(),
        recipient:
          addressString,
        amountRaw:
          unsignedInteger
      }).strict(),

      z.object({
        ...commonIntentFields,
        action:
          z.literal("erc20_approve"),
        asset:
          z.object({
            kind:
              z.literal("erc20"),
            address:
              addressString
          }).strict(),
        spender:
          addressString,
        amountRaw:
          unsignedInteger
      }).strict(),

      z.object({
        ...commonIntentFields,
        action:
          z.literal("erc20_transfer"),
        asset:
          z.object({
            kind:
              z.literal("erc20"),
            address:
              addressString
          }).strict(),
        recipient:
          addressString,
        amountRaw:
          unsignedInteger
      }).strict(),

      z.object({
        ...commonIntentFields,
        action:
          z.literal("erc20_transfer_from"),
        asset:
          z.object({
            kind:
              z.literal("erc20"),
            address:
              addressString
          }).strict(),
        owner:
          addressString,
        recipient:
          addressString,
        amountRaw:
          unsignedInteger
      }).strict(),

      z.object({
        ...commonIntentFields,
        action:
          z.literal("nft_set_approval_for_all"),
        asset:
          z.object({
            kind:
              z.literal("nft"),
            address:
              addressString
          }).strict(),
        operator:
          addressString,
        approved:
          z.boolean()
      }).strict()
    ]
  );

type DeclaredIntentCommon = {
  executionChainId: string;
  sender?: string;
  executionNonce?: string;
  validUntil?: string;
  targetCodeHash?: string;
  target: string;
  method?: string;
};

export type DeclaredIntent =
  | (DeclaredIntentCommon & {
      action: "native_transfer";
      asset: { kind: "native" };
      recipient: string;
      amountRaw: string;
    })
  | (DeclaredIntentCommon & {
      action: "erc20_approve";
      asset: { kind: "erc20"; address: string };
      spender: string;
      amountRaw: string;
    })
  | (DeclaredIntentCommon & {
      action: "erc20_transfer";
      asset: { kind: "erc20"; address: string };
      recipient: string;
      amountRaw: string;
    })
  | (DeclaredIntentCommon & {
      action: "erc20_transfer_from";
      asset: { kind: "erc20"; address: string };
      owner: string;
      recipient: string;
      amountRaw: string;
    })
  | (DeclaredIntentCommon & {
      action: "nft_set_approval_for_all";
      asset: { kind: "nft"; address: string };
      operator: string;
      approved: boolean;
    });

export type IntegrityFinding = {
  severity: "critical";
  code: string;
  message: string;
};

type ActualEffectBase = {
  chainKey: string;
  chainId: string;
  sender?: string;
  executionNonce?: string;
  target: string;
  valueWei: string;
  data: string;
};

export type KnownActualEffect =
  | (ActualEffectBase & {
      kind: "known";
      action: "native_transfer";
      method: "native_transfer";
      asset: {
        kind: "native";
      };
      recipient: string;
      amountRaw: string;
    })
  | (ActualEffectBase & {
      kind: "known";
      action: "erc20_approve";
      method: "approve(address,uint256)";
      asset: {
        kind: "erc20";
        address: string;
      };
      spender: string;
      amountRaw: string;
    })
  | (ActualEffectBase & {
      kind: "known";
      action: "erc20_transfer";
      method: "transfer(address,uint256)";
      asset: {
        kind: "erc20";
        address: string;
      };
      recipient: string;
      amountRaw: string;
    })
  | (ActualEffectBase & {
      kind: "known";
      action: "erc20_transfer_from";
      method: "transferFrom(address,address,uint256)";
      asset: {
        kind: "erc20";
        address: string;
      };
      owner: string;
      recipient: string;
      amountRaw: string;
    })
  | (ActualEffectBase & {
      kind: "known";
      action: "nft_set_approval_for_all";
      method: "setApprovalForAll(address,bool)";
      asset: {
        kind: "nft";
        address: string;
      };
      operator: string;
      approved: boolean;
    });

export type UnknownActualEffect =
  ActualEffectBase & {
    kind: "unknown";
    selector: string | null;
    reason: string;
  };

export type ActualEffect =
  | KnownActualEffect
  | UnknownActualEffect;

const effectInterface =
  new Interface([
    "function approve(address spender,uint256 amount)",
    "function transfer(address to,uint256 amount)",
    "function transferFrom(address from,address to,uint256 amount)",
    "function setApprovalForAll(address operator,bool approved)"
  ]);

function parseUnsignedInteger(
  value: string | undefined,
  fieldName: string
): bigint {
  const raw = value ?? "0";

  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `${fieldName} must be an unsigned integer`
    );
  }

  return BigInt(raw);
}

function normalizeAddress(
  value: string,
  fieldName: string
): string {
  if (!isAddress(value)) {
    throw new Error(
      `Invalid EVM address for ${fieldName}: ${value}`
    );
  }

  return getAddress(value);
}

function normalizeChainId(
  value: string
): string {
  if (!/^\d+$/.test(value)) {
    throw new Error(
      "executionChainId must be an unsigned integer"
    );
  }

  return BigInt(value).toString();
}

function validateCalldata(
  data: string
): void {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    throw new Error(
      "Transaction data must be hexadecimal bytes beginning with 0x"
    );
  }
}

export function decodeActualEffect(
  transaction: TransactionInput
): ActualEffect {
  const network =
    resolveNetwork(transaction.chain);

  const target =
    normalizeAddress(
      transaction.to,
      "transaction.to"
    );

  const sender =
    transaction.from
      ? normalizeAddress(
          transaction.from,
          "transaction.from"
        )
      : undefined;

  const data =
    transaction.data?.trim() || "0x";

  validateCalldata(data);

  const value =
    parseUnsignedInteger(
      transaction.valueWei,
      "valueWei"
    );

  const executionNonce =
    transaction.nonce === undefined
      ? undefined
      : parseUnsignedInteger(
          transaction.nonce,
          "nonce"
        ).toString();

  const base: ActualEffectBase = {
    chainKey: network.key,
    chainId:
      network.chainId.toString(),
    sender,
    executionNonce,
    target,
    valueWei:
      value.toString(),
    data
  };

  if (data === "0x") {
    if (value > 0n) {
      return {
        ...base,
        kind: "known",
        action: "native_transfer",
        method: "native_transfer",
        asset: {
          kind: "native"
        },
        recipient: target,
        amountRaw:
          value.toString()
      };
    }

    return {
      ...base,
      kind: "unknown",
      selector: null,
      reason:
        "Empty zero-value transaction has no supported security effect."
    };
  }

  try {
    const parsed =
      effectInterface.parseTransaction({
        data
      });

    if (!parsed) {
      throw new Error(
        "No known function matched calldata"
      );
    }

    const calldataBytes =
      (data.length - 2) / 2;

    const expectedCalldataBytes =
      parsed.name === "transferFrom"
        ? 100
        : parsed.name === "approve" ||
            parsed.name === "transfer" ||
            parsed.name === "setApprovalForAll"
          ? 68
          : null;

    if (
      expectedCalldataBytes === null ||
      calldataBytes !== expectedCalldataBytes
    ) {
      throw new Error(
        "Known selector has non-canonical calldata length"
      );
    }

    if (parsed.name === "approve") {
      return {
        ...base,
        kind: "known",
        action: "erc20_approve",
        method: "approve(address,uint256)",
        asset: {
          kind: "erc20",
          address: target
        },
        spender:
          getAddress(parsed.args[0]),
        amountRaw:
          BigInt(parsed.args[1]).toString()
      };
    }

    if (parsed.name === "transfer") {
      return {
        ...base,
        kind: "known",
        action: "erc20_transfer",
        method: "transfer(address,uint256)",
        asset: {
          kind: "erc20",
          address: target
        },
        recipient:
          getAddress(parsed.args[0]),
        amountRaw:
          BigInt(parsed.args[1]).toString()
      };
    }

    if (parsed.name === "transferFrom") {
      return {
        ...base,
        kind: "known",
        action: "erc20_transfer_from",
        method: "transferFrom(address,address,uint256)",
        asset: {
          kind: "erc20",
          address: target
        },
        owner:
          getAddress(parsed.args[0]),
        recipient:
          getAddress(parsed.args[1]),
        amountRaw:
          BigInt(parsed.args[2]).toString()
      };
    }

    if (parsed.name === "setApprovalForAll") {
      return {
        ...base,
        kind: "known",
        action: "nft_set_approval_for_all",
        method: "setApprovalForAll(address,bool)",
        asset: {
          kind: "nft",
          address: target
        },
        operator:
          getAddress(parsed.args[0]),
        approved:
          Boolean(parsed.args[1])
      };
    }
  } catch {}

  return {
    ...base,
    kind: "unknown",
    selector:
      data.length >= 10
        ? data.slice(0, 10).toLowerCase()
        : null,
    reason:
      "Calldata does not decode to a supported exact transaction effect."
  };
}

function pushMismatch(
  findings: IntegrityFinding[],
  code: string,
  message: string
): void {
  findings.push({
    severity: "critical",
    code,
    message
  });
}

function sameAddress(
  left: string,
  right: string
): boolean {
  return getAddress(left) === getAddress(right);
}

export function matchDeclaredIntent(
  declared: DeclaredIntent,
  actual: ActualEffect
) {
  const findings: IntegrityFinding[] = [];

  const declaredChainId =
    normalizeChainId(
      declared.executionChainId
    );

  if (
    declaredChainId !==
    actual.chainId
  ) {
    pushMismatch(
      findings,
      "CHAIN_MISMATCH",
      `Declared execution chain ${declaredChainId} does not match actual chain ${actual.chainId}.`
    );
  }

  if (!sameAddress(
    declared.target,
    actual.target
  )) {
    pushMismatch(
      findings,
      "TARGET_MISMATCH",
      `Declared target ${getAddress(declared.target)} does not match transaction target ${actual.target}.`
    );
  }

  if (declared.sender) {
    if (!actual.sender) {
      pushMismatch(
        findings,
        "SENDER_MISSING",
        "Declared intent constrains the sender, but the transaction has no sender."
      );
    } else if (!sameAddress(
      declared.sender,
      actual.sender
    )) {
      pushMismatch(
        findings,
        "SENDER_MISMATCH",
        `Declared sender ${getAddress(declared.sender)} does not match transaction sender ${actual.sender}.`
      );
    }
  }

  if (declared.executionNonce !== undefined) {
    const declaredNonce =
      parseUnsignedInteger(
        declared.executionNonce,
        "executionNonce"
      ).toString();

    if (actual.executionNonce === undefined) {
      pushMismatch(
        findings,
        "EXECUTION_NONCE_MISSING",
        "Declared intent constrains the execution nonce, but the transaction has no nonce."
      );
    } else if (declaredNonce !== actual.executionNonce) {
      pushMismatch(
        findings,
        "EXECUTION_NONCE_MISMATCH",
        `Declared execution nonce ${declaredNonce} does not match transaction nonce ${actual.executionNonce}.`
      );
    }
  }

  if (actual.kind === "unknown") {
    pushMismatch(
      findings,
      "UNKNOWN_ACTUAL_EFFECT",
      actual.reason
    );

    return {
      ok: false as const,
      decision: "BLOCK" as const,
      findings
    };
  }

  if (declared.action !== actual.action) {
    pushMismatch(
      findings,
      "ACTION_MISMATCH",
      `Declared action ${declared.action} does not match decoded action ${actual.action}.`
    );

    return {
      ok: false as const,
      decision: "BLOCK" as const,
      findings
    };
  }

  if (
    actual.action !== "native_transfer" &&
    BigInt(actual.valueWei) !== 0n
  ) {
    pushMismatch(
      findings,
      "UNEXPECTED_NATIVE_VALUE",
      `Decoded ${actual.action} transaction also sends ${actual.valueWei} wei; supported intent actions require zero native value.`
    );
  }

  if (
    declared.method !== undefined &&
    declared.method !== actual.method
  ) {
    pushMismatch(
      findings,
      "METHOD_MISMATCH",
      `Declared method ${declared.method} does not match decoded method ${actual.method}.`
    );
  }

  if (declared.asset.kind !== actual.asset.kind) {
    pushMismatch(
      findings,
      "ASSET_KIND_MISMATCH",
      `Declared asset kind ${declared.asset.kind} does not match decoded asset kind ${actual.asset.kind}.`
    );
  }

  if (
    "address" in declared.asset &&
    "address" in actual.asset &&
    !sameAddress(
      declared.asset.address,
      actual.asset.address
    )
  ) {
    pushMismatch(
      findings,
      "ASSET_MISMATCH",
      `Declared asset ${getAddress(declared.asset.address)} does not match decoded asset ${actual.asset.address}.`
    );
  }

  switch (declared.action) {
    case "native_transfer": {
      if (
        actual.action === "native_transfer"
      ) {
        if (!sameAddress(
          declared.recipient,
          actual.recipient
        )) {
          pushMismatch(
            findings,
            "RECIPIENT_MISMATCH",
            `Declared recipient ${getAddress(declared.recipient)} does not match decoded recipient ${actual.recipient}.`
          );
        }

        if (
          BigInt(declared.amountRaw) !==
          BigInt(actual.amountRaw)
        ) {
          pushMismatch(
            findings,
            "AMOUNT_MISMATCH",
            `Declared amount ${BigInt(declared.amountRaw).toString()} does not match decoded amount ${actual.amountRaw}.`
          );
        }
      }
      break;
    }

    case "erc20_approve": {
      if (
        actual.action === "erc20_approve"
      ) {
        if (!sameAddress(
          declared.spender,
          actual.spender
        )) {
          pushMismatch(
            findings,
            "SPENDER_MISMATCH",
            `Declared spender ${getAddress(declared.spender)} does not match decoded spender ${actual.spender}.`
          );
        }

        if (
          BigInt(declared.amountRaw) !==
          BigInt(actual.amountRaw)
        ) {
          pushMismatch(
            findings,
            "AMOUNT_MISMATCH",
            `Declared amount ${BigInt(declared.amountRaw).toString()} does not match decoded amount ${actual.amountRaw}.`
          );
        }
      }
      break;
    }

    case "erc20_transfer": {
      if (
        actual.action === "erc20_transfer"
      ) {
        if (!sameAddress(
          declared.recipient,
          actual.recipient
        )) {
          pushMismatch(
            findings,
            "RECIPIENT_MISMATCH",
            `Declared recipient ${getAddress(declared.recipient)} does not match decoded recipient ${actual.recipient}.`
          );
        }

        if (
          BigInt(declared.amountRaw) !==
          BigInt(actual.amountRaw)
        ) {
          pushMismatch(
            findings,
            "AMOUNT_MISMATCH",
            `Declared amount ${BigInt(declared.amountRaw).toString()} does not match decoded amount ${actual.amountRaw}.`
          );
        }
      }
      break;
    }

    case "erc20_transfer_from": {
      if (
        actual.action === "erc20_transfer_from"
      ) {
        if (!sameAddress(
          declared.owner,
          actual.owner
        )) {
          pushMismatch(
            findings,
            "OWNER_MISMATCH",
            `Declared owner ${getAddress(declared.owner)} does not match decoded owner ${actual.owner}.`
          );
        }

        if (!sameAddress(
          declared.recipient,
          actual.recipient
        )) {
          pushMismatch(
            findings,
            "RECIPIENT_MISMATCH",
            `Declared recipient ${getAddress(declared.recipient)} does not match decoded recipient ${actual.recipient}.`
          );
        }

        if (
          BigInt(declared.amountRaw) !==
          BigInt(actual.amountRaw)
        ) {
          pushMismatch(
            findings,
            "AMOUNT_MISMATCH",
            `Declared amount ${BigInt(declared.amountRaw).toString()} does not match decoded amount ${actual.amountRaw}.`
          );
        }
      }
      break;
    }

    case "nft_set_approval_for_all": {
      if (
        actual.action === "nft_set_approval_for_all"
      ) {
        if (!sameAddress(
          declared.operator,
          actual.operator
        )) {
          pushMismatch(
            findings,
            "OPERATOR_MISMATCH",
            `Declared operator ${getAddress(declared.operator)} does not match decoded operator ${actual.operator}.`
          );
        }

        if (
          declared.approved !==
          actual.approved
        ) {
          pushMismatch(
            findings,
            "APPROVAL_FLAG_MISMATCH",
            `Declared approved=${String(declared.approved)} does not match decoded approved=${String(actual.approved)}.`
          );
        }
      }
      break;
    }
  }

  return {
    ok:
      findings.length === 0,
    decision:
      findings.length === 0
        ? "ALLOW" as const
        : "BLOCK" as const,
    findings
  };
}
