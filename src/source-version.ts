import {
  execFileSync
} from "node:child_process";

import {
  createHash
} from "node:crypto";

import {
  readFileSync,
  readdirSync
} from "node:fs";

import path from "node:path";
import { fileURLToPath } from "node:url";

export type SourceVersionSnapshot = {
  sourceId: string;
  sourceKind: "git" | "standalone-sha256";
  sourceCommit?: string;
  treeClean: boolean | null;
};

const currentFile =
  fileURLToPath(import.meta.url);

const projectRoot =
  path.resolve(
    path.dirname(currentFile),
    ".."
  );

function git(
  args: string[]
): string {
  return execFileSync(
    "git",
    ["-C", projectRoot, ...args],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }
  ).trim();
}

function samePath(
  a: string,
  b: string
): boolean {
  const left = path.resolve(a);
  const right = path.resolve(b);

  return process.platform === "win32"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function gitSnapshot(): SourceVersionSnapshot | null {
  try {
    const topLevel =
      git(["rev-parse", "--show-toplevel"]);

    if (!samePath(topLevel, projectRoot)) {
      return null;
    }

    const commit = git(["rev-parse", "HEAD"]);
    const status = git([
      "status",
      "--porcelain",
      "--untracked-files=all"
    ]);

    if (!/^[0-9a-f]{40}$/i.test(commit)) {
      return null;
    }

    return {
      sourceId: `git:${commit.toLowerCase()}`,
      sourceKind: "git",
      sourceCommit: commit.toLowerCase(),
      treeClean: status.length === 0
    };
  } catch {
    return null;
  }
}

function sourceFiles(): string[] {
  const roots = [
    "src",
    "contracts",
    "scripts",
    "public"
  ];

  const fixed = [
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    ".env.example"
  ];

  const files = [...fixed];

  const visit = (relativeDir: string): void => {
    const absoluteDir =
      path.join(projectRoot, relativeDir);

    const entries =
      readdirSync(
        absoluteDir,
        { withFileTypes: true }
      )
        .sort((a, b) =>
          a.name.localeCompare(b.name)
        );

    for (const entry of entries) {
      const relative =
        path.join(relativeDir, entry.name);

      if (entry.isDirectory()) {
        visit(relative);
        continue;
      }

      if (entry.isFile()) {
        files.push(relative);
        continue;
      }

      throw new Error(
        `Unsupported source entry for standalone fingerprint: ${relative}`
      );
    }
  };

  for (const relativeDir of roots) {
    visit(relativeDir);
  }

  return files
    .map((file) => file.split(path.sep).join("/"))
    .sort();
}

function standaloneSnapshot(): SourceVersionSnapshot {
  const hash = createHash("sha256");

  hash.update(
    "AgentFirewall.SourceFingerprint.v1\0"
  );

  for (const relative of sourceFiles()) {
    const absolute =
      path.join(
        projectRoot,
        ...relative.split("/")
      );

    hash.update(relative);
    hash.update("\0");
    hash.update(readFileSync(absolute));
    hash.update("\0");
  }

  return {
    sourceId: `sha256:${hash.digest("hex")}`,
    sourceKind: "standalone-sha256",
    treeClean: null
  };
}

export function sourceVersionSnapshot(): SourceVersionSnapshot {
  return gitSnapshot() ?? standaloneSnapshot();
}

export function requireEvidenceSourceVersion(): SourceVersionSnapshot {
  const snapshot = sourceVersionSnapshot();

  if (
    snapshot.sourceKind === "git" &&
    snapshot.treeClean === false &&
    process.env.AGENTFIREWALL_ALLOW_DIRTY_EVIDENCE !== "true"
  ) {
    throw new Error(
      "Dirty Git tree: submission evidence requires a clean source snapshot. AGENTFIREWALL_ALLOW_DIRTY_EVIDENCE=true is debug-only."
    );
  }

  return snapshot;
}
