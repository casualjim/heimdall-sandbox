#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
workspace_version() {
  awk '
    /^\[workspace.package\]$/ { in_workspace_package=1; next }
    /^\[/ { in_workspace_package=0 }
    in_workspace_package && /^version[[:space:]]*=/ { gsub(/\"/, "", $3); print $3; exit }
  ' Cargo.toml
}

WORKSPACE_VERSION=$(workspace_version)
if [[ -z "${VERSION}" ]]; then
  VERSION="${WORKSPACE_VERSION}"
fi
if [[ -z "${VERSION}" ]]; then
  echo "release version is required" >&2
  exit 1
fi
if [[ "${VERSION}" != "${WORKSPACE_VERSION}" ]]; then
  echo "release version ${VERSION} does not match workspace.package.version ${WORKSPACE_VERSION}" >&2
  exit 1
fi

CRATES=(
  "heimdall-process-hardening"
  "heimdall-sandbox-policy"
  "heimdall-linux-sandbox"
  "heimdall-macos-sandbox"
  "heimdall-core"
  "heimdall-sandbox"
)

crate_version_exists() {
  local crate="$1"
  local version="$2"
  local status
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/${crate}/${version}")
  case "${status}" in
    200) return 0 ;;
    404) return 1 ;;
    *) echo "crates.io version lookup failed for ${crate} ${version}: HTTP ${status}" >&2; return 2 ;;
  esac
}

wait_for_crate_version() {
  local crate="$1"
  local version="$2"
  for _ in $(seq 1 30); do
    if crate_version_exists "${crate}" "${version}"; then
      return 0
    fi
    sleep 10
  done
  echo "${crate} ${version} did not appear in crates.io index after publishing" >&2
  return 1
}

for crate in "${CRATES[@]}"; do
  if crate_version_exists "${crate}" "${VERSION}"; then
    echo "${crate} ${VERSION} already exists on crates.io; skipping"
    continue
  fi

  echo "Publishing ${crate} ${VERSION} to crates.io"
  cargo publish --locked --package "${crate}" --token "${CARGO_REGISTRY_TOKEN-}"
  wait_for_crate_version "${crate}" "${VERSION}"
done
