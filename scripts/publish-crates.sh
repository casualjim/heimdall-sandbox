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

PUBLISH_MAX_ATTEMPTS="${PUBLISH_MAX_ATTEMPTS:-5}"
PUBLISH_RETRY_DELAY_SECONDS="${PUBLISH_RETRY_DELAY_SECONDS:-10}"
PUBLISH_SUCCESS_DELAY_SECONDS="${PUBLISH_SUCCESS_DELAY_SECONDS:-10}"

CRATES=(
  "heimdall-process-hardening"
  "heimdall-sandbox-policy"
  "heimdall-linux-sandbox"
  "heimdall-macos-sandbox"
  "heimdall-core"
  "heimdall-privacy-filter"
  "heimdall-sandbox"
)

publish_crate() {
  local crate="$1"
  local attempt
  local output
  for attempt in $(seq 1 "${PUBLISH_MAX_ATTEMPTS}"); do
    echo "Publishing ${crate} ${VERSION} to crates.io (attempt ${attempt}/${PUBLISH_MAX_ATTEMPTS})"
    if output=$(cargo publish --locked --package "${crate}" --token "${CARGO_REGISTRY_TOKEN-}" 2>&1); then
      printf '%s\n' "${output}"
      return 0
    fi

    printf '%s\n' "${output}" >&2
    if grep -Eiq 'already (uploaded|exists)|crate version .* is already uploaded|version .* already exists' <<<"${output}"; then
      echo "${crate} ${VERSION} already exists on crates.io; skipping"
      return 0
    fi

    if [[ "${attempt}" == "${PUBLISH_MAX_ATTEMPTS}" ]]; then
      echo "failed to publish ${crate} ${VERSION} after ${PUBLISH_MAX_ATTEMPTS} attempts" >&2
      return 1
    fi

    echo "publish failed for ${crate} ${VERSION}; retrying in ${PUBLISH_RETRY_DELAY_SECONDS}s" >&2
    sleep "${PUBLISH_RETRY_DELAY_SECONDS}"
  done
}

for crate in "${CRATES[@]}"; do
  publish_crate "${crate}"
  sleep "${PUBLISH_SUCCESS_DELAY_SECONDS}"
done
