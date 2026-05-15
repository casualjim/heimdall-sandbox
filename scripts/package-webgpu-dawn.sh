#!/usr/bin/env bash
set -euo pipefail

TARGET_TRIPLE="${1:?target triple required}"
MANIFEST="${2:-dist-manifest.json}"
ARTIFACT_DIR="target/distrib/heimdall-sandbox-${TARGET_TRIPLE}"
ARCHIVE="${ARTIFACT_DIR}.tar.xz"
CHECKSUM="${ARCHIVE}.sha256"
ARCHIVE_BASENAME="$(basename "${ARCHIVE}")"

case "${TARGET_TRIPLE}" in
  aarch64-unknown-linux-gnu)
    echo "skipping WebGPU Dawn packaging for CPU-only Linux arm64 build"
    exit 0
    ;;
  *-apple-darwin)
    LIB_NAME="libwebgpu_dawn.dylib"
    ;;
  *-unknown-linux-gnu)
    LIB_NAME="libwebgpu_dawn.so"
    ;;
  *)
    echo "unsupported target for WebGPU Dawn packaging: ${TARGET_TRIPLE}" >&2
    exit 1
    ;;
esac

if [[ ! -d "${ARTIFACT_DIR}" ]]; then
  echo "missing cargo-dist artifact directory: ${ARTIFACT_DIR}" >&2
  exit 1
fi

# The dylib is next to the binary in the build output.
CANDIDATES=(
  "target/${TARGET_TRIPLE}/dist/${LIB_NAME}"
  "target/${TARGET_TRIPLE}/release/${LIB_NAME}"
  "target/release/${LIB_NAME}"
)

LIB_PATH=""
for candidate in "${CANDIDATES[@]}"; do
  if [[ -f "${candidate}" || -L "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" || ! -e "${LIB_PATH}" ]]; then
  echo "missing ${LIB_NAME}; searched target build outputs" >&2
  exit 1
fi

cp -L "${LIB_PATH}" "${ARTIFACT_DIR}/${LIB_NAME}"

# Rebuild the archive with the dylib included.
tar -C target/distrib -cJf "${ARCHIVE}" "$(basename "${ARTIFACT_DIR}")"

# Recompute the checksum.
if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
else
  HASH="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
fi
printf '%s *%s\n' "${HASH}" "${ARCHIVE_BASENAME}" > "${CHECKSUM}"

# Patch the dist manifest with the new checksum so downstream consumers
# (Homebrew formula, upload list) stay consistent.
if [[ -f "${MANIFEST}" ]] && command -v jq >/dev/null 2>&1; then
  jq --arg archive "${ARCHIVE_BASENAME}" --arg hash "${HASH}" \
    'if .artifacts[$archive].checksums.sha256 then .artifacts[$archive].checksums.sha256 = $hash else . end' \
    "${MANIFEST}" > "${MANIFEST}.tmp" && mv "${MANIFEST}.tmp" "${MANIFEST}"
fi
