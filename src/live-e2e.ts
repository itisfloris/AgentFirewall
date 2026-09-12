import {
  spawnSync
} from "node:child_process";

import {
  readFileSync
} from "node:fs";

import {
  Wallet
} from "ethers";

import {
  DEFAULT_LIVE_EVIDENCE_FILE,
  type LiveJudgeEvidence
} from "./live-evidence.js";

import {
  requireEvidenceSourceVersion
} from "./source-version.js";

function requiredEnv(
  name: string
): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `${name} is required for the fresh live E2E run`
    );
  }

  return value;
}

function run(
  script: string,
  extraEnv: NodeJS.ProcessEnv = {}
): void {
  const npmExecPath = process.env.npm_execpath?.trim();

  if (!npmExecPath) {
    throw new Error(
      "npm_execpath is missing; run live:e2e through npm"
    );
  }

  const result = spawnSync(
    process.execPath,
    [npmExecPath, "run", script],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        ...extraEnv
      },
      stdio: "inherit"
    }
  );

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(
      `${script} failed with exit code ${String(result.status)}`
    );
  }
}

function main(): void {
  const source = requireEvidenceSourceVersion();

  requiredEnv("SEPOLIA_RPC_URL");
  requiredEnv("CREDITCOIN_RPC_URL");
  requiredEnv("AGENTFIREWALL_TESTNET_PRIVATE_KEY");
  requiredEnv("AGENTFIREWALL_CONTROLLER_PRIVATE_KEY");
  requiredEnv("AGENTFIREWALL_MAX_GAS_LIMIT");
  requiredEnv("AGENTFIREWALL_MAX_FEE_PER_GAS_WEI");
  requiredEnv("AGENTFIREWALL_MAX_PRIORITY_FEE_PER_GAS_WEI");
  requiredEnv("AGENTFIREWALL_MAX_TOTAL_FEE_WEI");

  const executor = new Wallet(
    requiredEnv("AGENTFIREWALL_TESTNET_PRIVATE_KEY")
  );
  const controller = new Wallet(
    requiredEnv("AGENTFIREWALL_CONTROLLER_PRIVATE_KEY")
  );

  if (executor.address === controller.address) {
    throw new Error(
      "Fresh E2E requires separate executor and controller keys"
    );
  }

  console.log(
    `AgentFirewall fresh E2E sourceId=${source.sourceId} sourceKind=${source.sourceKind} treeClean=${String(source.treeClean)}`
  );
  console.log(
    `executor=${executor.address} controller=${controller.address}`
  );

  run("attestcoin:publish-demo-authorization");
  run("attestcoin:ingest-authorization");
  run("controller:approve-live");
  run(
    "demo:verified-live",
    {
      AGENTFIREWALL_LIVE_SEND: "true"
    }
  );
  run("live:evidence");

  const evidencePath =
    process.env.AGENTFIREWALL_LIVE_EVIDENCE_FILE?.trim() ||
    DEFAULT_LIVE_EVIDENCE_FILE;
  const evidence = JSON.parse(
    readFileSync(evidencePath, "utf8")
  ) as LiveJudgeEvidence;

  console.log(
    JSON.stringify(
      {
        result: "FRESH LIVE E2E COMPLETE",
        sourceId:
          evidence.build?.sourceId ??
          (evidence.build?.sourceCommit
            ? `git:${evidence.build.sourceCommit}`
            : null),
        sourceKind:
          evidence.build?.sourceKind ??
          (evidence.build?.sourceCommit
            ? "git"
            : null),
        sourceTransactionHash:
          evidence.source.transactionHash,
        creditcoinTransactionHash:
          evidence.creditcoin.transactionHash,
        executionTransactionHash:
          evidence.execution?.transactionHash ?? null,
        mutated:
          evidence.guardedSigner?.mutated ?? null,
        canonical:
          evidence.guardedSigner?.canonical ?? null,
        evidence: evidencePath
      },
      null,
      2
    )
  );
}

try {
  main();
} catch (error) {
  console.error(
    error instanceof Error
      ? error.message
      : error
  );
  process.exitCode = 1;
}
