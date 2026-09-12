import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const currentFile = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(currentFile), "..");
const tsxCli = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

if (!existsSync(tsxCli)) {
  throw new Error("Dependencies are missing. Run `npm ci` first.");
}

const child = spawnSync(
  process.execPath,
  [tsxCli, "src/judge-runtime.ts"],
  {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    env: process.env
  }
);

if (child.error) {
  throw child.error;
}

if (child.status !== 0) {
  throw new Error(
    `Runtime judge process failed with exit code ${child.status}.\n${child.stdout}${child.stderr}`
  );
}

const line = child.stdout
  .split(/\r?\n/)
  .find((entry) => entry.startsWith("JUDGE_RUNTIME_RESULT "));

if (!line) {
  throw new Error(`Runtime judge result was not emitted.\n${child.stdout}${child.stderr}`);
}

const x = JSON.parse(line.slice("JUDGE_RUNTIME_RESULT ".length));

assert(
  x.proofKind === "runtime-current-guarded-signer",
  "Runtime verifier did not execute the current GuardedSigner path."
);
assert(x.mutated?.simulation === "SUCCESS", "Mutated simulation is not SUCCESS.");
assert(x.mutated?.decision === "BLOCK", "Mutated candidate was not BLOCKed.");
assert(x.mutated?.signTransactionCalls === 0, "Mutated candidate reached signTransaction.");
assert(x.mutated?.rawBroadcastObserved === false, "Mutated candidate reached broadcast.");

assert(x.canonical?.simulation === "SUCCESS", "Canonical simulation is not SUCCESS.");
assert(x.canonical?.decision === "ALLOW", "Canonical candidate was not ALLOWed.");
assert(x.canonical?.signTransactionCalls === 1, "Canonical candidate did not call signTransaction exactly once.");
assert(x.canonical?.rawBroadcastObserved === true, "Canonical candidate was not broadcast by the instrumented provider.");
assert(
  /^0x[0-9a-fA-F]{64}$/.test(x.canonical?.transactionHash ?? ""),
  "Canonical runtime transaction hash is missing or malformed."
);

console.log("=== RUNTIME SECURITY VERIFICATION ===");
console.log(
  `COMPROMISED : ${x.mutated.simulation} -> ${x.mutated.decision} -> signTransaction calls ${x.mutated.signTransactionCalls}`
);
console.log(
  `AUTHORIZED  : ${x.canonical.simulation} -> ${x.canonical.decision} -> signTransaction calls ${x.canonical.signTransactionCalls}`
);
console.log("Current GuardedSigner.guardAndSendVerified(): executed");
console.log("Historical bundled evidence: not used for these decisions");
console.log("=== JUDGE VERIFY PASS ===");
