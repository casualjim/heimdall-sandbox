#!/usr/bin/env bash
# Patches the dist-generated Homebrew formula to install the WebGPU Dawn
# shared library alongside the binaries and add the necessary rpath/codesign.
set -euo pipefail

FORMULA_PATH="${1:?formula path required}"

if [[ ! -f "${FORMULA_PATH}" ]]; then
  echo "formula not found: ${FORMULA_PATH}" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ruby "${SCRIPT_DIR}/patch-homebrew-formula.rb" "$FORMULA_PATH"
