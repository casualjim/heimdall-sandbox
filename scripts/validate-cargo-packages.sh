#!/usr/bin/env bash
set -euo pipefail

CRATES=(
  "heimdall-process-hardening"
  "heimdall-sandbox-policy"
  "heimdall-linux-sandbox"
  "heimdall-macos-sandbox"
  "heimdall-core"
  "heimdall-sandbox"
)

for crate in "${CRATES[@]}"; do
  echo "Listing package contents for ${crate}"
  cargo package --list --allow-dirty --package "${crate}" >/dev/null
done
