#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION=$(awk '
    /^\[workspace.package\]$/ { in_workspace_package=1; next }
    /^\[/ { in_workspace_package=0 }
    in_workspace_package && /^version[[:space:]]*=/ { gsub(/\"/, "", $3); print $3; exit }
  ' Cargo.toml)
fi
if [[ -z "${VERSION}" ]]; then
  echo "release version is required" >&2
  exit 1
fi

ARTIFACTS_DIR="${ARTIFACTS_DIR:-target/distrib}"
OUT_DIR="${OUT_DIR:-target/npm-packages}"

node scripts/prepare-npm-packages.ts --version "${VERSION}" --artifacts-dir "${ARTIFACTS_DIR}" --out-dir "${OUT_DIR}" --pack-dry-run

PACKAGES=(
  "heimdall-sandbox-linux-x64:@casualjim/heimdall-sandbox-linux-x64"
  "heimdall-sandbox-linux-arm64:@casualjim/heimdall-sandbox-linux-arm64"
  "heimdall-sandbox-darwin-arm64:@casualjim/heimdall-sandbox-darwin-arm64"
  "heimdall-sandbox:@casualjim/heimdall-sandbox"
)

npm_version_exists() {
  local package="$1"
  local version="$2"
  npm view "${package}@${version}" version --silent >/dev/null 2>&1
}

for entry in "${PACKAGES[@]}"; do
  dir_name="${entry%%:*}"
  package_name="${entry#*:}"
  package_dir="${OUT_DIR}/${dir_name}"

  if npm_version_exists "${package_name}" "${VERSION}"; then
    echo "${package_name} ${VERSION} already exists on npm; skipping"
    continue
  fi

  echo "Publishing ${package_name} ${VERSION} to npm"
  npm publish "${package_dir}" --access public --provenance
done
