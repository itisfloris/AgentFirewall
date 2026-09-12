import {
  Interface,
  MaxUint256,
  ZeroAddress,
  getAddress,
  isAddress
} from "ethers";

export type TransactionInput = {
  chain?: string;
  from?: string;
  to: string;
  data?: string;
  valueWei?: string;
  nonce?: string;
};

export type SecurityPolicy = {
  maxNativeValueWei?: string;
  allowedTargets?: string[];
  blockedTargets?: string[];
  requireKnownCalldata?: boolean;
};

export type Finding = {
  severity: "info" | "medium" | "high" | "critical";
  code: string;
  message: string;
};

const commonInterface = new Interface([
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

  if (raw.length > 78 || !/^\d+$/.test(raw)) {
    throw new Error(`${fieldName} must be an unsigned integer`);
  }

  return BigInt(raw);
}

function normalizeAddressList(
  values: string[] | undefined,
  fieldName: string
): string[] {
  if (!values) {
    return [];
  }

  if (values.length > 128) {
    throw new Error(`${fieldName} exceeds the 128-address policy bound`);
  }

  return values.map((value) => {
    if (!isAddress(value)) {
      throw new Error(`Invalid address in ${fieldName}: ${value}`);
    }

    return getAddress(value);
  });
}

function validateCalldata(data: string): void {
  if (data.length > 131074) {
    throw new Error(
      "Transaction data exceeds the 64 KiB AgentFirewall input bound"
    );
  }

  if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    throw new Error(
      "Transaction data must be hexadecimal bytes beginning with 0x"
    );
  }
}

function stringifyArgument(value: unknown): string {
  if (typeof value === "bigint") {
    return value.toString();
  }

  return String(value);
}

export function analyzeTransaction(
  input: TransactionInput,
  policy: SecurityPolicy = {}
) {
  if (!isAddress(input.to)) {
    throw new Error("Invalid EVM destination address");
  }

  if (input.from && !isAddress(input.from)) {
    throw new Error("Invalid EVM sender address");
  }

  const target = getAddress(input.to);
  const sender = input.from ? getAddress(input.from) : undefined;

  const data = input.data?.trim() || "0x";
  validateCalldata(data);

  const value = parseUnsignedInteger(
    input.valueWei,
    "valueWei"
  );

  const findings: Finding[] = [];

  let score = 0;
  let intent = "Unknown contract interaction";
  let method: string | null = null;
  let argumentsDecoded: string[] = [];

  const blockedTargets = normalizeAddressList(
    policy.blockedTargets,
    "blockedTargets"
  );

  const allowedTargets = normalizeAddressList(
    policy.allowedTargets,
    "allowedTargets"
  );

  if (target === ZeroAddress) {
    score += 70;

    findings.push({
      severity: "critical",
      code: "ZERO_TARGET",
      message: "Transaction targets the zero address."
    });
  }

  if (blockedTargets.includes(target)) {
    score += 100;

    findings.push({
      severity: "critical",
      code: "BLOCKED_TARGET",
      message:
        "The destination address is explicitly blocked by the active security policy."
    });
  }

  if (
    allowedTargets.length > 0 &&
    !allowedTargets.includes(target)
  ) {
    score += 70;

    findings.push({
      severity: "critical",
      code: "TARGET_NOT_ALLOWED",
      message:
        "The destination is not present in the active allowlist."
    });
  }

  if (policy.maxNativeValueWei !== undefined) {
    const maximum = parseUnsignedInteger(
      policy.maxNativeValueWei,
      "maxNativeValueWei"
    );

    if (value > maximum) {
      score += 70;

      findings.push({
        severity: "critical",
        code: "SPENDING_LIMIT_EXCEEDED",
        message:
          `Transaction sends ${value.toString()} wei, exceeding the configured limit of ${maximum.toString()} wei.`
      });
    }
  }

  if (data === "0x") {
    if (value > 0n) {
      intent = `Native token transfer: ${value.toString()} wei`;
      method = "native_transfer";
    } else {
      intent = "Empty transaction";
      method = "empty";
    }
  } else {
    try {
      const parsed = commonInterface.parseTransaction({
        data
      });

      if (!parsed) {
        throw new Error("Unknown calldata");
      }

      method = parsed.name;

      argumentsDecoded = Array
        .from(parsed.args)
        .map(stringifyArgument);

      if (parsed.name === "approve") {
        const spender = getAddress(parsed.args[0]);
        const amount = BigInt(parsed.args[1]);

        intent = `ERC-20 approval for ${spender}`;

        if (amount === MaxUint256) {
          score += 80;

          findings.push({
            severity: "critical",
            code: "UNLIMITED_APPROVAL",
            message:
              "Unlimited ERC-20 allowance requested. The spender could potentially move the entire token balance."
          });
        } else if (amount > 0n) {
          score += 20;

          findings.push({
            severity: "medium",
            code: "TOKEN_APPROVAL",
            message:
              `ERC-20 allowance requested: ${amount.toString()} token units.`
          });
        }

        if (spender === ZeroAddress) {
          findings.push({
            severity: "info",
            code: "ZERO_SPENDER",
            message:
              "Approval spender is the zero address."
          });
        }
      }

      if (parsed.name === "setApprovalForAll") {
        const operator = getAddress(parsed.args[0]);
        const approved = Boolean(parsed.args[1]);

        intent = `NFT operator approval for ${operator}`;

        if (approved) {
          score += 75;

          findings.push({
            severity: "critical",
            code: "NFT_APPROVAL_FOR_ALL",
            message:
              "The operator receives permission to control every compatible NFT owned by the wallet."
          });
        }
      }

      if (parsed.name === "transfer") {
        const receiver = getAddress(parsed.args[0]);
        const amount = BigInt(parsed.args[1]);

        intent =
          `ERC-20 transfer of ${amount.toString()} units to ${receiver}`;

        score += 5;
      }

      if (parsed.name === "transferFrom") {
        const from = getAddress(parsed.args[0]);
        const receiver = getAddress(parsed.args[1]);
        const amount = BigInt(parsed.args[2]);

        intent =
          `transferFrom ${from} -> ${receiver}, ${amount.toString()} units`;

        score += 20;

        findings.push({
          severity: "medium",
          code: "TRANSFER_FROM",
          message:
            "Transaction attempts to move assets using an existing allowance."
        });
      }
    } catch {
      const strictUnknown =
        policy.requireKnownCalldata === true;

      score += strictUnknown ? 70 : 35;

      findings.push({
        severity: strictUnknown
          ? "critical"
          : "high",
        code: "UNKNOWN_CALLDATA",
        message: strictUnknown
          ? "Unknown contract calls are forbidden by the active security policy."
          : "AgentFirewall cannot decode this contract call yet. It should be manually reviewed before signing."
      });
    }
  }

  if (value > 0n && data !== "0x") {
    score += 15;

    findings.push({
      severity: "medium",
      code: "VALUE_AND_CALL",
      message:
        "The transaction sends native currency while also executing contract calldata."
    });
  }

  score = Math.min(score, 100);

  const risk =
    score >= 70
      ? "critical"
      : score >= 40
        ? "high"
        : score >= 20
          ? "medium"
          : "low";

  const decision =
    score >= 70
      ? "BLOCK"
      : score >= 40
        ? "REVIEW"
        : "ALLOW";

  return {
    chain: input.chain || "evm",
    sender,
    target,
    valueWei: value.toString(),
    transactionSummary: intent,
    intent,
    decoded: {
      method,
      arguments: argumentsDecoded
    },
    risk,
    score,
    decision,
    findings
  };
}
