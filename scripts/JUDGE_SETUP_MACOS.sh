#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This launcher is for macOS. Use JUDGE_SETUP_LINUX.sh on Linux." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v node >/dev/null 2>&1 || { echo "Node.js >=20 is required." >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is required." >&2; exit 1; }
MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[[ "$MAJOR" -ge 20 ]] || { echo "Node.js >=20 is required; found $(node --version)." >&2; exit 1; }

echo "=== macOS / NODE ==="
sw_vers
node --version
npm --version

echo "=== CLEAN INSTALL ==="
npm ci

echo "=== LOCAL VALIDATION ==="
npm run validate:local

echo "=== HEADLESS JUDGE VERIFY ==="
npm run judge:verify

echo "=== macOS JUDGE SETUP PASS ==="
echo "Next: run npm run dev and open http://127.0.0.1:8787 to inspect the visual judge demo."
