import {
  isHexString
} from "ethers";

import {
  commitmentFromActualEffect,
  commitmentFromDeclaredIntent
} from "./authorization.js";

import type {
  DeclaredIntent,
  IntegrityFinding
} from "./intent.js";

export type VerifiedAuthorizationRecord = {
  authorizationId: string;
  commitment: string;
  verified: boolean;
  sourceChainKey: string;
  sourceBlockNumber: string;
  transactionIndex: string;
  validUntil: string;
  registryAddress?: string;
  creditcoinChainId?: string;
  rpcSource?: string;
  registryTrustAnchorsVerified?: boolean;
  registryRuntimeCodeHashVerified?: boolean;
  registrySnapshotBlockNumber?: string;
  registrySnapshotBlockHash?: string;
};

export interface VerifiedAuthorizationReader {
  getAuthorization(
    authorizationId: string
  ): Promise<VerifiedAuthorizationRecord | null>;
}

export type AuthorizationFinding =
  IntegrityFinding;

export type AuthorizationIntegrity = {
  ok: boolean;
  decision: "ALLOW" | "BLOCK";
  authorizationId: string;
  registryRecord: VerifiedAuthorizationRecord | null;
  declaredCommitment: string | null;
  actualCommitment: string | null;
  actualTargetCodeHash: string | null;
  findings: AuthorizationFinding[];
};

export function critical(
  code: string,
  message: string
): AuthorizationFinding {
  return {
    severity: "critical",
    code,
    message
  };
}

export function normalizeAuthorizationId(
  value: string
): string {
  if (!isHexString(value, 32)) {
    throw new Error(
      "authorizationId must be exactly 32 bytes"
    );
  }

  return value.toLowerCase();
}

function normalizeUint64(
  value: string,
  field: string
): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(
      `${field} must be an unsigned decimal integer`
    );
  }

  const parsed = BigInt(value);
  const maxUint64 = (1n << 64n) - 1n;

  if (parsed > maxUint64) {
    throw new Error(
      `${field} exceeds uint64`
    );
  }

  return parsed.toString();
}

export function normalizeCommitment(
  value: string,
  field: string
): string {
  if (!isHexString(value, 32)) {
    throw new Error(
      `${field} must be exactly 32 bytes`
    );
  }

  return value.toLowerCase();
}

export async function evaluateVerifiedAuthorization(
  authorizationId: string,
  declaredIntent: DeclaredIntent,
  actualEffect: Parameters<typeof commitmentFromActualEffect>[0],
  actualTargetCodeHash: string,
  reader: VerifiedAuthorizationReader,
  chainTimeSeconds: number
): Promise<AuthorizationIntegrity> {
  if (
    !Number.isSafeInteger(chainTimeSeconds) ||
    chainTimeSeconds < 0
  ) {
    throw new Error(
      "Verified authorization requires an execution-chain block timestamp"
    );
  }
  const normalizedId =
    normalizeAuthorizationId(
      authorizationId
    );

  const findings: AuthorizationFinding[] = [];
  let registryRecord: VerifiedAuthorizationRecord | null = null;
  let declaredCommitment: string | null = null;
  let actualCommitment: string | null = null;
  let normalizedActualTargetCodeHash: string | null = null;

  try {
    normalizedActualTargetCodeHash =
      normalizeCommitment(
        actualTargetCodeHash,
        "actual target code hash"
      );
  } catch (error) {
    findings.push(
      critical(
        "ACTUAL_TARGET_CODE_HASH_INVALID",
        error instanceof Error
          ? error.message
          : "Actual target code hash is malformed"
      )
    );
  }

  if (declaredIntent.targetCodeHash === undefined) {
    findings.push(
      critical(
        "DECLARED_TARGET_CODE_HASH_MISSING",
        "Verified authorization mode requires declaredIntent.targetCodeHash."
      )
    );
  } else {
    try {
      const declaredTargetCodeHash =
        normalizeCommitment(
          declaredIntent.targetCodeHash,
          "declared target code hash"
        );

      if (
        normalizedActualTargetCodeHash &&
        declaredTargetCodeHash !== normalizedActualTargetCodeHash
      ) {
        findings.push(
          critical(
            "TARGET_CODE_HASH_MISMATCH",
            `Declared target code hash ${declaredTargetCodeHash} does not match live target code hash ${normalizedActualTargetCodeHash}.`
          )
        );
      }
    } catch (error) {
      findings.push(
        critical(
          "DECLARED_TARGET_CODE_HASH_INVALID",
          error instanceof Error
            ? error.message
            : "Declared target code hash is malformed"
        )
      );
    }
  }

  try {
    declaredCommitment =
      normalizeCommitment(
        commitmentFromDeclaredIntent(
          declaredIntent
        ),
        "declared commitment"
      );
  } catch (error) {
    findings.push(
      critical(
        "DECLARED_AUTHORIZATION_UNCOMMITTABLE",
        error instanceof Error
          ? error.message
          : "Declared intent cannot be committed"
      )
    );
  }

  try {
    registryRecord =
      await reader.getAuthorization(
        normalizedId
      );
  } catch (error) {
    findings.push(
      critical(
        "VERIFIED_AUTHORIZATION_UNAVAILABLE",
        `Creditcoin verified-authorization lookup failed: ${
          error instanceof Error
            ? error.message
            : "unknown error"
        }`
      )
    );
  }

  if (!registryRecord) {
    if (
      !findings.some(
        finding =>
          finding.code ===
          "VERIFIED_AUTHORIZATION_UNAVAILABLE"
      )
    ) {
      findings.push(
        critical(
          "VERIFIED_AUTHORIZATION_NOT_FOUND",
          `No verified authorization exists for ${normalizedId}.`
        )
      );
    }

    if (
      normalizedActualTargetCodeHash &&
      declaredIntent.validUntil !== undefined
    ) {
      try {
        actualCommitment =
          normalizeCommitment(
            commitmentFromActualEffect(
              actualEffect,
              normalizedActualTargetCodeHash,
              normalizeUint64(
                declaredIntent.validUntil,
                "declared validUntil"
              )
            ),
            "actual commitment"
          );
      } catch {
      }
    }
  } else {
    let recordCommitment: string | null = null;

    try {
      recordCommitment =
        normalizeCommitment(
          registryRecord.commitment,
          "registry commitment"
        );
    } catch (error) {
      findings.push(
        critical(
          "VERIFIED_AUTHORIZATION_INVALID",
          error instanceof Error
            ? error.message
            : "Registry authorization record is malformed"
        )
      );
    }

    if (!registryRecord.verified) {
      findings.push(
        critical(
          "VERIFIED_AUTHORIZATION_NOT_VERIFIED",
          `Authorization ${normalizedId} is present but is not marked verified by the Creditcoin registry.`
        )
      );
    }

    let recordValidUntil: string | null = null;

    try {
      recordValidUntil =
        normalizeUint64(
          registryRecord.validUntil,
          "registry validUntil"
        );

      if (recordValidUntil === "0") {
        throw new Error(
          "registry validUntil must be greater than zero"
        );
      }
    } catch (error) {
      findings.push(
        critical(
          "VERIFIED_AUTHORIZATION_INVALID",
          error instanceof Error
            ? error.message
            : "Registry authorization expiry is malformed"
        )
      );
    }

    let declaredValidUntil: string | null = null;

    if (declaredIntent.validUntil === undefined) {
      findings.push(
        critical(
          "DECLARED_VALID_UNTIL_MISSING",
          "Verified authorization mode requires declaredIntent.validUntil."
        )
      );
    } else {
      try {
        declaredValidUntil =
          normalizeUint64(
            declaredIntent.validUntil,
            "declared validUntil"
          );

        if (declaredValidUntil === "0") {
          throw new Error(
            "declared validUntil must be greater than zero"
          );
        }
      } catch (error) {
        findings.push(
          critical(
            "DECLARED_VALID_UNTIL_INVALID",
            error instanceof Error
              ? error.message
              : "Declared authorization expiry is malformed"
          )
        );
      }
    }

    if (
      recordValidUntil &&
      declaredValidUntil &&
      recordValidUntil !== declaredValidUntil
    ) {
      findings.push(
        critical(
          "VERIFIED_VALID_UNTIL_MISMATCH",
          `Creditcoin validUntil ${recordValidUntil} does not match declared validUntil ${declaredValidUntil}.`
        )
      );
    }

    if (
      recordValidUntil &&
      BigInt(recordValidUntil) <= BigInt(chainTimeSeconds)
    ) {
      findings.push(
        critical(
          "VERIFIED_AUTHORIZATION_EXPIRED",
          `Verified authorization expired at unix time ${recordValidUntil}.`
        )
      );
    }

    if (
      normalizedActualTargetCodeHash &&
      recordValidUntil
    ) {
      try {
        actualCommitment =
          normalizeCommitment(
            commitmentFromActualEffect(
              actualEffect,
              normalizedActualTargetCodeHash,
              recordValidUntil
            ),
            "actual commitment"
          );
      } catch (error) {
        findings.push(
          critical(
            "ACTUAL_AUTHORIZATION_UNCOMMITTABLE",
            error instanceof Error
              ? error.message
              : "Actual transaction effect cannot be committed"
          )
        );
      }
    } else if (!normalizedActualTargetCodeHash) {
      findings.push(
        critical(
          "ACTUAL_AUTHORIZATION_UNCOMMITTABLE",
          "Actual transaction cannot be committed without a valid live target code hash."
        )
      );
    }

    if (
      recordCommitment &&
      declaredCommitment &&
      recordCommitment !== declaredCommitment
    ) {
      findings.push(
        critical(
          "VERIFIED_DECLARED_COMMITMENT_MISMATCH",
          `Creditcoin commitment ${recordCommitment} does not match declared-intent commitment ${declaredCommitment}.`
        )
      );
    }

    if (
      recordCommitment &&
      actualCommitment &&
      recordCommitment !== actualCommitment
    ) {
      findings.push(
        critical(
          "VERIFIED_ACTUAL_COMMITMENT_MISMATCH",
          `Creditcoin commitment ${recordCommitment} does not match actual-transaction commitment ${actualCommitment}.`
        )
      );
    }
  }

  return {
    ok: findings.length === 0,
    decision:
      findings.length === 0
        ? "ALLOW"
        : "BLOCK",
    authorizationId:
      normalizedId,
    registryRecord,
    declaredCommitment,
    actualCommitment,
    actualTargetCodeHash:
      normalizedActualTargetCodeHash,
    findings
  };
}
