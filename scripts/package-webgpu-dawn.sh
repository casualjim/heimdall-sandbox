#!/usr/bin/env bash
set -euo pipefail

TARGET_TRIPLE="${1:?target triple required}"
ARTIFACT_DIR="target/distrib/heimdall-sandbox-${TARGET_TRIPLE}"
ARCHIVE="${ARTIFACT_DIR}.tar.xz"
CHECKSUM="${ARCHIVE}.sha256"

case "${TARGET_TRIPLE}" in
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

CANDIDATES=(
  "target/${TARGET_TRIPLE}/dist/${LIB_NAME}"
  "target/${TARGET_TRIPLE}/release/${LIB_NAME}"
  "target/release/${LIB_NAME}"
)

LIB_PATH=""
for candidate in "${CANDIDATES[@]}"; do
  if [[ -e "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  LIB_PATH="$(find target -path "*/${LIB_NAME}" -print -quit)"
fi

if [[ -z "${LIB_PATH}" || ! -e "${LIB_PATH}" ]]; then
  echo "missing ${LIB_NAME}; searched target build outputs" >&2
  exit 1
fi

cp -L "${LIB_PATH}" "${ARTIFACT_DIR}/${LIB_NAME}"

tar -C target/distrib -cJf "${ARCHIVE}" "$(basename "${ARTIFACT_DIR}")"

if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
else
  HASH="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
fi
printf '%s *%s\n' "${HASH}" "$(basename "${ARCHIVE}")" > "${CHECKSUM}"
