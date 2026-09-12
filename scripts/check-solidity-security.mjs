import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";

const files = {
  source: "contracts/AuthorizationSource.sol",
  registry: "contracts/VerifiedAuthorizationRegistry.sol",
  sourceAbi: "build/contracts/AuthorizationSource.abi",
  registryAbi: "build/contracts/VerifiedAuthorizationRegistry.abi",
  sourceRuntime: "build/contracts/AuthorizationSource.runtime.bin",
  registryRuntime: "build/contracts/VerifiedAuthorizationRegistry.runtime.bin"
};

for (const path of Object.values(files)) {
  if (!existsSync(path)) {
    throw new Error(`Missing Solidity security input: ${path}`);
  }
}

const source = readFileSync(files.source, "utf8");
const registry = readFileSync(files.registry, "utf8");
const sourceAbi = JSON.parse(readFileSync(files.sourceAbi, "utf8"));
const registryAbi = JSON.parse(readFileSync(files.registryAbi, "utf8"));
const sourceRuntime = readFileSync(files.sourceRuntime, "utf8").trim();
const registryRuntime = readFileSync(files.registryRuntime, "utf8").trim();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function abiNames(abi, type) {
  return new Set(
    abi.filter((entry) => entry?.type === type).map((entry) => entry.name)
  );
}

assert(source.includes('keccak256("AgentFirewall.Authorization.v3")'), "Authorization.v3 domain changed unexpectedly");
assert(source.includes("authorization.sender != msg.sender"), "AuthorizationSource sender authentication is missing");
assert(source.includes("authorization.validUntil <= block.timestamp"), "AuthorizationSource expiry check is missing");
assert(registry.includes("processedTransactions[transactionKey]"), "Registry replay guard is missing");
assert(registry.includes("eventData.validUntil <= block.timestamp"), "Registry expiry check is missing");
assert(registry.includes("trustedCount != 1"), "Registry exact-one-event rule is missing");

const forbidden = ["tx.origin", "selfdestruct(", "delegatecall("];
for (const token of forbidden) {
  assert(!source.includes(token), `AuthorizationSource contains forbidden primitive ${token}`);
  assert(!registry.includes(token), `VerifiedAuthorizationRegistry contains forbidden primitive ${token}`);
}

const sourceFunctions = abiNames(sourceAbi, "function");
const registryFunctions = abiNames(registryAbi, "function");
const sourceEvents = abiNames(sourceAbi, "event");
const registryEvents = abiNames(registryAbi, "event");

for (const name of ["publishAuthorization", "computeCommitment", "computeExecutionBinding", "nextNonce"]) {
  assert(sourceFunctions.has(name), `AuthorizationSource ABI is missing ${name}`);
}
assert(sourceEvents.has("AuthorizationPublished"), "AuthorizationSource ABI is missing AuthorizationPublished");
for (const name of ["submitVerifiedAuthorization", "getAuthorization", "getAuthorizationEvidence", "computeTransactionKey"]) {
  assert(registryFunctions.has(name), `VerifiedAuthorizationRegistry ABI is missing ${name}`);
}
assert(registryEvents.has("VerifiedAuthorizationRecorded"), "Registry ABI is missing VerifiedAuthorizationRecorded");
assert(/^[0-9a-fA-F]+$/.test(sourceRuntime) && sourceRuntime.length > 100, "AuthorizationSource runtime artifact is invalid");
assert(/^[0-9a-fA-F_]+$/.test(registryRuntime) && registryRuntime.length > 100, "Registry runtime artifact is invalid");

const digest = createHash("sha256")
  .update(source)
  .update("\0")
  .update(registry)
  .update("\0")
  .update(sourceRuntime)
  .update("\0")
  .update(registryRuntime)
  .digest("hex");

console.log(JSON.stringify({
  contractCompilationArtifactsPresent: true,
  authorizationSenderAuthentication: true,
  authorizationExpiryGuard: true,
  registryReplayGuard: true,
  registryExactOneEventGuard: true,
  forbiddenPrimitiveScan: true,
  criticalAbiSurfacePresent: true,
  sourceAndRuntimeDigestSha256: digest
}, null, 2));
