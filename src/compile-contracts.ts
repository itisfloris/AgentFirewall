import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";

import {
  dirname,
  isAbsolute,
  join,
  normalize,
  posix,
  resolve
} from "node:path";

import {
  spawnSync
} from "node:child_process";

const outputDirectory =
  "build/contracts";

const rootArtifacts = [
  {
    source: "contracts/AuthorizationSource.sol",
    contract: "AuthorizationSource"
  },
  {
    source: "contracts/VerifiedAuthorizationRegistry.sol",
    contract: "VerifiedAuthorizationRegistry"
  }
] as const;

const decoderArtifact = {
  source:
    "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol",
  contract:
    "EvmV1Decoder"
} as const;

const sourceImportPattern =
  /import\s+(?:(?:\{[^}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*)\s+from\s+)?["']([^"']+)["']\s*;/g;

type SourceMap = Record<
  string,
  { content: string }
>;

function toLogicalPath(
  path: string
): string {
  return path.replaceAll("\\", "/");
}

function resolvePackageFilesystemPath(
  importPath: string
): string {
  return resolve(
    "node_modules",
    ...importPath.split("/")
  );
}

function resolveImport(
  importerLogicalPath: string,
  importerFilesystemPath: string,
  importPath: string
): {
  logicalPath: string;
  filesystemPath: string;
} {
  if (importPath.startsWith(".")) {
    return {
      logicalPath:
        posix.normalize(
          posix.join(
            posix.dirname(
              importerLogicalPath
            ),
            importPath
          )
        ),
      filesystemPath:
        normalize(
          join(
            dirname(
              importerFilesystemPath
            ),
            importPath
          )
        )
    };
  }

  if (isAbsolute(importPath)) {
    throw new Error(
      `Absolute Solidity import is not allowed: ${importPath}`
    );
  }

  return {
    logicalPath:
      toLogicalPath(importPath),
    filesystemPath:
      resolvePackageFilesystemPath(
        importPath
      )
  };
}

function collectSoliditySources(): SourceMap {
  const sources: SourceMap = {};
  const visited = new Set<string>();

  function visit(
    logicalPath: string,
    filesystemPath: string
  ): void {
    const normalizedLogical =
      toLogicalPath(
        posix.normalize(logicalPath)
      );

    if (visited.has(normalizedLogical)) {
      return;
    }

    if (!existsSync(filesystemPath)) {
      throw new Error(
        [
          `Unable to resolve Solidity source ${normalizedLogical}.`,
          `Expected file: ${filesystemPath}`,
          normalizedLogical.startsWith("@gluwa/asc-contracts/")
            ? "Missing optional compiler dependency: @gluwa/asc-contracts@0.2.1"
            : null
        ]
          .filter(Boolean)
          .join("\n")
      );
    }

    visited.add(normalizedLogical);

    const content =
      readFileSync(
        filesystemPath,
        "utf8"
      );

    sources[normalizedLogical] = {
      content
    };

    const imports =
      Array.from(
        content.matchAll(sourceImportPattern),
        match => match[1]
      );

    for (const importPath of imports) {
      const resolved = resolveImport(
        normalizedLogical,
        filesystemPath,
        importPath
      );

      visit(
        resolved.logicalPath,
        resolved.filesystemPath
      );
    }
  }

  for (const artifact of rootArtifacts) {
    visit(
      artifact.source,
      resolve(artifact.source)
    );
  }

  return sources;
}

const solcPackagePath =
  resolve("node_modules/solc/package.json");
const solcCliPath =
  resolve("node_modules/solc/solc.js");
const decoderPackagePath =
  resolve("node_modules/@gluwa/asc-contracts/package.json");

if (
  !existsSync(solcPackagePath) ||
  !existsSync(solcCliPath) ||
  !existsSync(decoderPackagePath)
) {
  throw new Error(
    "Optional Solidity compilation requires locally installed solc@0.8.28 and @gluwa/asc-contracts@0.2.1. The compiler never installs packages at runtime."
  );
}

const solcPackage = JSON.parse(
  readFileSync(solcPackagePath, "utf8")
) as { version?: string };
const decoderPackage = JSON.parse(
  readFileSync(decoderPackagePath, "utf8")
) as { version?: string };

if (solcPackage.version !== "0.8.28") {
  throw new Error(
    `Expected solc@0.8.28, found ${String(solcPackage.version)}`
  );
}

if (decoderPackage.version !== "0.2.1") {
  throw new Error(
    `Expected @gluwa/asc-contracts@0.2.1, found ${String(decoderPackage.version)}`
  );
}

rmSync(
  outputDirectory,
  {
    recursive: true,
    force: true
  }
);

mkdirSync(
  outputDirectory,
  {
    recursive: true
  }
);

const compilerInput = {
  language: "Solidity",
  sources: collectSoliditySources(),
  settings: {
    optimizer: {
      enabled: true,
      runs: 200
    },
    viaIR: true,
    evmVersion: "shanghai",
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode.object",
          "evm.bytecode.linkReferences",
          "evm.deployedBytecode.object",
          "evm.deployedBytecode.linkReferences",
          "evm.deployedBytecode.immutableReferences"
        ]
      }
    }
  }
};

const result = spawnSync(
  process.execPath,
  [
    solcCliPath,
    "--standard-json"
  ],
  {
    input: JSON.stringify(compilerInput),
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: false
  }
);

if (result.error) {
  throw result.error;
}

if (result.status !== 0) {
  throw new Error(
    [
      `Solidity compiler process failed with exit code ${result.status ?? "unknown"}.`,
      result.stderr?.trim()
    ]
      .filter(Boolean)
      .join("\n")
  );
}

const stdout =
  result.stdout ?? "";

const jsonStart =
  stdout.indexOf("{");
const jsonEnd =
  stdout.lastIndexOf("}");

if (
  jsonStart < 0 ||
  jsonEnd < jsonStart
) {
  throw new Error(
    [
      "Solidity compiler did not return Standard JSON output.",
      stdout.trim(),
      result.stderr?.trim()
    ]
      .filter(Boolean)
      .join("\n")
  );
}

type CompilerDiagnostic = {
  severity?: string;
  formattedMessage?: string;
  message?: string;
};

type LinkReference = {
  start: number;
  length: number;
};

type CompilerContract = {
  abi?: unknown[];
  evm?: {
    bytecode?: {
      object?: string;
      linkReferences?: Record<
        string,
        Record<string, LinkReference[]>
      >;
    };
    deployedBytecode?: {
      object?: string;
      linkReferences?: Record<
        string,
        Record<string, LinkReference[]>
      >;
      immutableReferences?: Record<
        string,
        LinkReference[]
      >;
    };
  };
};

type CompilerOutput = {
  errors?: CompilerDiagnostic[];
  contracts?: Record<
    string,
    Record<string, CompilerContract>
  >;
};

let output: CompilerOutput;

try {
  output = JSON.parse(
    stdout.slice(
      jsonStart,
      jsonEnd + 1
    )
  ) as CompilerOutput;
} catch (error) {
  throw new Error(
    `solc JSON parse failed: ${
      error instanceof Error
        ? error.message
        : String(error)
    }`
  );
}

const diagnostics =
  output.errors ?? [];

for (const diagnostic of diagnostics) {
  const message =
    diagnostic.formattedMessage ??
    diagnostic.message ??
    "Unknown Solidity compiler diagnostic";

  if (diagnostic.severity === "error") {
    console.error(message.trim());
  } else {
    console.warn(message.trim());
  }
}

const compilerErrors =
  diagnostics.filter(
    diagnostic =>
      diagnostic.severity === "error"
  );

if (compilerErrors.length > 0) {
  throw new Error(
    `Solidity compilation failed with ${compilerErrors.length} compiler error(s).`
  );
}

function writeArtifact(
  source: string,
  contract: string
): void {
  const artifact =
    output.contracts?.[source]?.[contract];

  if (!artifact) {
    throw new Error(
      `Solidity output is missing ${contract} from ${source}.`
    );
  }

  if (!Array.isArray(artifact.abi)) {
    throw new Error(
      `Solidity output for ${contract} is missing its ABI.`
    );
  }

  const bytecode =
    artifact.evm?.bytecode?.object;

  if (
    typeof bytecode !== "string" ||
    bytecode.length === 0
  ) {
    throw new Error(
      `Solidity output for ${contract} is missing deployable bytecode.`
    );
  }

  const linkReferences =
    artifact.evm?.bytecode?.linkReferences ?? {};

  const deployedBytecode =
    artifact.evm?.deployedBytecode?.object ?? "";

  const runtimeLinkReferences =
    artifact.evm?.deployedBytecode?.linkReferences ?? {};

  const runtimeImmutableReferences =
    artifact.evm?.deployedBytecode?.immutableReferences ?? {};

  writeFileSync(
    `${outputDirectory}/${contract}.abi`,
    `${JSON.stringify(artifact.abi, null, 2)}\n`,
    "utf8"
  );

  writeFileSync(
    `${outputDirectory}/${contract}.bin`,
    `${bytecode}\n`,
    "utf8"
  );

  writeFileSync(
    `${outputDirectory}/${contract}.links.json`,
    `${JSON.stringify(linkReferences, null, 2)}\n`,
    "utf8"
  );

  if (deployedBytecode) {
    writeFileSync(
      `${outputDirectory}/${contract}.runtime.bin`,
      `${deployedBytecode}\n`,
      "utf8"
    );

    writeFileSync(
      `${outputDirectory}/${contract}.runtime.links.json`,
      `${JSON.stringify(runtimeLinkReferences, null, 2)}\n`,
      "utf8"
    );

    writeFileSync(
      `${outputDirectory}/${contract}.runtime.immutables.json`,
      `${JSON.stringify(runtimeImmutableReferences, null, 2)}\n`,
      "utf8"
    );
  }

  const linkCount =
    Object.values(linkReferences)
      .flatMap(sourceLibraries =>
        Object.values(sourceLibraries)
      )
      .reduce(
        (count, references) =>
          count + references.length,
        0
      );

  const deploymentSizeLabel =
    /^[0-9a-fA-F]+$/.test(bytecode)
      ? `${bytecode.length / 2} byte(s)`
      : `${bytecode.length} encoded character(s) before library linking`;

  console.log(
    `[SOLC] ${contract}: ABI + ${deploymentSizeLabel}; link references=${linkCount}`
  );
}

for (const artifact of rootArtifacts) {
  writeArtifact(
    artifact.source,
    artifact.contract
  );
}

writeArtifact(
  decoderArtifact.source,
  decoderArtifact.contract
);

console.log(
  "Solidity 0.8.28 compile PASS (optimizer=200, viaIR=true, evmVersion=shanghai)."
);
console.log(
  `Solidity artifacts written to ${outputDirectory}`
);
