import { readFileSync } from "node:fs";

const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const root = lock.packages?.[""];

if (!root) {
  throw new Error("package-lock.json has no root package entry");
}

const exactVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
for (const section of ["dependencies", "devDependencies"]) {
  const declared = packageJson[section] ?? {};
  const lockedRoot = root[section] ?? {};

  for (const [name, version] of Object.entries(declared)) {
    if (!exactVersion.test(String(version))) {
      throw new Error(`${section}.${name} is not an exact version: ${version}`);
    }
    if (lockedRoot[name] !== version) {
      throw new Error(`${section}.${name} differs between package.json (${version}) and package-lock root (${lockedRoot[name]})`);
    }
    const pkg = lock.packages?.[`node_modules/${name}`];
    if (!pkg || pkg.version !== version) {
      throw new Error(`${name}@${version} is not exactly represented in package-lock.json`);
    }
  }
}

const allowedLicenses = new Set(["MIT", "Apache-2.0", "ISC", "BSD-3-Clause", "0BSD"]);
const installScripts = [];
const licenseCounts = new Map();
let registryPackages = 0;

for (const [location, pkg] of Object.entries(lock.packages ?? {})) {
  if (!location || !location.startsWith("node_modules/")) continue;

  const license = pkg.license;
  if (!license || !allowedLicenses.has(license)) {
    throw new Error(`${location} has missing/unreviewed license ${String(license)}`);
  }
  licenseCounts.set(license, (licenseCounts.get(license) ?? 0) + 1);

  if (pkg.hasInstallScript) {
    installScripts.push(`${location}@${pkg.version}`);
  }

  if (pkg.resolved) {
    registryPackages += 1;
    if (!String(pkg.resolved).startsWith("https://registry.npmjs.org/")) {
      throw new Error(`${location} resolves outside registry.npmjs.org: ${pkg.resolved}`);
    }
    if (!pkg.integrity || !String(pkg.integrity).startsWith("sha512-")) {
      throw new Error(`${location} is missing sha512 package-lock integrity`);
    }
  }
}

const expectedInstallScripts = new Set([
  "node_modules/esbuild@0.28.2",
  "node_modules/fsevents@2.3.3"
]);
for (const item of installScripts) {
  if (!expectedInstallScripts.has(item)) {
    throw new Error(`Unexpected package with install script: ${item}`);
  }
}
for (const item of expectedInstallScripts) {
  if (!installScripts.includes(item)) {
    throw new Error(`Expected reviewed install-script package disappeared/changed: ${item}`);
  }
}

console.log(JSON.stringify({
  exactTopLevelVersions: true,
  packageLockRootMatches: true,
  reviewedLicenseSet: Object.fromEntries([...licenseCounts.entries()].sort()),
  reviewedInstallScriptPackages: installScripts.sort(),
  registryPackagesWithIntegrityChecked: registryPackages,
  note: "This audits the mandatory application package-lock. Optional Solidity recompilation dependencies are outside this lockfile; no runtime package acquisition is performed and full Solidity rebuild hermeticity is not claimed."
}, null, 2));
