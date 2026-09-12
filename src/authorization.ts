import {
  AbiCoder,
  Interface,
  ZeroAddress,
  getAddress,
  id,
  isHexString,
  keccak256
} from "ethers";

import type {
  ActualEffect,
  DeclaredIntent,
  KnownActualEffect
} from "./intent.js";

export const AUTHORIZATION_COMMITMENT_DOMAIN =
  id("AgentFirewall.Authorization.v3");

const ACTION_CODE = {
  native_transfer: 1,
  erc20_approve: 2,
  erc20_transfer: 3,
  erc20_transfer_from: 4,
  nft_set_approval_for_all: 5
} as const;

export type AuthorizationAction =
  keyof typeof ACTION_CODE;

export type CanonicalAuthorization = {
  domain: string;
  executionChainId: string;
  sender: string;
  executionNonce: string;
  validUntil: string;
  action: AuthorizationAction;
  actionCode: number;
  target: string;
  targetCodeHash: string;
  asset: string;
  counterpartyA: string;
  counterpartyB: string;
  amountOrFlag: string;
  callDataHash: string;
  nativeValueWei: string;
};

const coder =
  AbiCoder.defaultAbiCoder();

const callInterface =
  new Interface([
    "function approve(address spender,uint256 amount)",
    "function transfer(address to,uint256 amount)",
    "function transferFrom(address from,address to,uint256 amount)",
    "function setApprovalForAll(address operator,bool approved)"
  ]);

function normalizeUint(
  value: string,
  field: string
): string {
  if (!/^\d+$/.test(value)) {
    throw new Error(
      `${field} must be an unsigned integer`
    );
  }

  return BigInt(value).toString();
}

function normalizeUint64(
  value: string | undefined,
  field: string
): string {
  if (value === undefined || !/^\d+$/.test(value)) {
    throw new Error(
      `${field} must be an unsigned uint64 integer`
    );
  }

  const parsed = BigInt(value);
  const max = (1n << 64n) - 1n;

  if (parsed > max) {
    throw new Error(
      `${field} exceeds uint64`
    );
  }

  return parsed.toString();
}

function normalizeBytes32(
  value: string | undefined,
  field: string
): string {
  if (!value || !isHexString(value, 32)) {
    throw new Error(
      `${field} must be exactly 32 bytes`
    );
  }

  return value.toLowerCase();
}

function requireSender(
  sender: string | undefined,
  context: string
): string {
  if (!sender) {
    throw new Error(
      `${context} must include an exact sender in verified-authorization mode`
    );
  }

  return getAddress(sender);
}

function requireExecutionNonce(
  nonce: string | undefined,
  context: string
): string {
  if (nonce === undefined) {
    throw new Error(
      `${context} must include an exact executionNonce in verified-authorization mode`
    );
  }

  return normalizeUint(
    nonce,
    "executionNonce"
  );
}

function canonicalBase(
  executionChainId: string,
  sender: string | undefined,
  executionNonce: string | undefined,
  validUntil: string | undefined,
  action: AuthorizationAction,
  target: string,
  targetCodeHash: string | undefined
) {
  return {
    domain:
      AUTHORIZATION_COMMITMENT_DOMAIN,
    executionChainId:
      normalizeUint(
        executionChainId,
        "executionChainId"
      ),
    sender:
      requireSender(
        sender,
        "Authorization"
      ),
    executionNonce:
      requireExecutionNonce(
        executionNonce,
        "Authorization"
      ),
    validUntil:
      normalizeUint64(
        validUntil,
        "validUntil"
      ),
    action,
    actionCode:
      ACTION_CODE[action],
    target:
      getAddress(target),
    targetCodeHash:
      normalizeBytes32(
        targetCodeHash,
        "targetCodeHash"
      )
  };
}

function declaredCallBinding(
  intent: DeclaredIntent
): {
  callDataHash: string;
  nativeValueWei: string;
} {
  switch (intent.action) {
    case "native_transfer":
      return {
        callDataHash:
          keccak256("0x"),
        nativeValueWei:
          normalizeUint(
            intent.amountRaw,
            "amountRaw"
          )
      };

    case "erc20_approve":
      return {
        callDataHash:
          keccak256(
            callInterface.encodeFunctionData(
              "approve",
              [
                intent.spender,
                BigInt(intent.amountRaw)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case "erc20_transfer":
      return {
        callDataHash:
          keccak256(
            callInterface.encodeFunctionData(
              "transfer",
              [
                intent.recipient,
                BigInt(intent.amountRaw)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case "erc20_transfer_from":
      return {
        callDataHash:
          keccak256(
            callInterface.encodeFunctionData(
              "transferFrom",
              [
                intent.owner,
                intent.recipient,
                BigInt(intent.amountRaw)
              ]
            )
          ),
        nativeValueWei: "0"
      };

    case "nft_set_approval_for_all":
      return {
        callDataHash:
          keccak256(
            callInterface.encodeFunctionData(
              "setApprovalForAll",
              [
                intent.operator,
                intent.approved
              ]
            )
          ),
        nativeValueWei: "0"
      };
  }
}

export function canonicalizeDeclaredIntent(
  intent: DeclaredIntent
): CanonicalAuthorization {
  const base =
    canonicalBase(
      intent.executionChainId,
      intent.sender,
      intent.executionNonce,
      intent.validUntil,
      intent.action,
      intent.target,
      intent.targetCodeHash
    );

  const callBinding =
    declaredCallBinding(intent);

  switch (intent.action) {
    case "native_transfer":
      return {
        ...base,
        asset: ZeroAddress,
        counterpartyA:
          getAddress(intent.recipient),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            intent.amountRaw,
            "amountRaw"
          ),
        ...callBinding
      };

    case "erc20_approve":
      return {
        ...base,
        asset:
          getAddress(intent.asset.address),
        counterpartyA:
          getAddress(intent.spender),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            intent.amountRaw,
            "amountRaw"
          ),
        ...callBinding
      };

    case "erc20_transfer":
      return {
        ...base,
        asset:
          getAddress(intent.asset.address),
        counterpartyA:
          getAddress(intent.recipient),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            intent.amountRaw,
            "amountRaw"
          ),
        ...callBinding
      };

    case "erc20_transfer_from":
      return {
        ...base,
        asset:
          getAddress(intent.asset.address),
        counterpartyA:
          getAddress(intent.owner),
        counterpartyB:
          getAddress(intent.recipient),
        amountOrFlag:
          normalizeUint(
            intent.amountRaw,
            "amountRaw"
          ),
        ...callBinding
      };

    case "nft_set_approval_for_all":
      return {
        ...base,
        asset:
          getAddress(intent.asset.address),
        counterpartyA:
          getAddress(intent.operator),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          intent.approved ? "1" : "0",
        ...callBinding
      };
  }
}

export function canonicalizeActualEffect(
  effect: ActualEffect,
  targetCodeHash: string,
  validUntil: string
): CanonicalAuthorization {
  if (effect.kind !== "known") {
    throw new Error(
      "Unknown actual effect cannot produce a verified authorization commitment"
    );
  }

  return canonicalizeKnownActualEffect(
    effect,
    targetCodeHash,
    validUntil
  );
}

function canonicalizeKnownActualEffect(
  effect: KnownActualEffect,
  targetCodeHash: string,
  validUntil: string
): CanonicalAuthorization {
  const base =
    canonicalBase(
      effect.chainId,
      effect.sender,
      effect.executionNonce,
      validUntil,
      effect.action,
      effect.target,
      targetCodeHash
    );

  const byteBinding = {
    callDataHash:
      keccak256(effect.data),
    nativeValueWei:
      normalizeUint(
        effect.valueWei,
        "valueWei"
      )
  };

  switch (effect.action) {
    case "native_transfer":
      return {
        ...base,
        asset: ZeroAddress,
        counterpartyA:
          getAddress(effect.recipient),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            effect.amountRaw,
            "amountRaw"
          ),
        ...byteBinding
      };

    case "erc20_approve":
      return {
        ...base,
        asset:
          getAddress(effect.asset.address),
        counterpartyA:
          getAddress(effect.spender),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            effect.amountRaw,
            "amountRaw"
          ),
        ...byteBinding
      };

    case "erc20_transfer":
      return {
        ...base,
        asset:
          getAddress(effect.asset.address),
        counterpartyA:
          getAddress(effect.recipient),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          normalizeUint(
            effect.amountRaw,
            "amountRaw"
          ),
        ...byteBinding
      };

    case "erc20_transfer_from":
      return {
        ...base,
        asset:
          getAddress(effect.asset.address),
        counterpartyA:
          getAddress(effect.owner),
        counterpartyB:
          getAddress(effect.recipient),
        amountOrFlag:
          normalizeUint(
            effect.amountRaw,
            "amountRaw"
          ),
        ...byteBinding
      };

    case "nft_set_approval_for_all":
      return {
        ...base,
        asset:
          getAddress(effect.asset.address),
        counterpartyA:
          getAddress(effect.operator),
        counterpartyB: ZeroAddress,
        amountOrFlag:
          effect.approved ? "1" : "0",
        ...byteBinding
      };
  }
}

export function computeAuthorizationCommitment(
  authorization: CanonicalAuthorization
): string {
  const encoded =
    coder.encode(
      [
        "bytes32",
        "uint256",
        "address",
        "uint256",
        "uint64",
        "uint8",
        "address",
        "bytes32",
        "address",
        "address",
        "address",
        "uint256",
        "bytes32",
        "uint256"
      ],
      [
        authorization.domain,
        authorization.executionChainId,
        authorization.sender,
        authorization.executionNonce,
        authorization.validUntil,
        authorization.actionCode,
        authorization.target,
        authorization.targetCodeHash,
        authorization.asset,
        authorization.counterpartyA,
        authorization.counterpartyB,
        authorization.amountOrFlag,
        authorization.callDataHash,
        authorization.nativeValueWei
      ]
    );

  return keccak256(encoded);
}

export function commitmentFromDeclaredIntent(
  intent: DeclaredIntent
): string {
  return computeAuthorizationCommitment(
    canonicalizeDeclaredIntent(intent)
  );
}

export function commitmentFromActualEffect(
  effect: ActualEffect,
  targetCodeHash: string,
  validUntil: string
): string {
  return computeAuthorizationCommitment(
    canonicalizeActualEffect(
      effect,
      targetCodeHash,
      validUntil
    )
  );
}
