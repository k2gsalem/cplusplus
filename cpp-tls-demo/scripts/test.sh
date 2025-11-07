#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$(mktemp)"
trap 'rm -f "${LOG_FILE}"' EXIT

pushd "${ROOT_DIR}" >/dev/null

# Ensure the binaries are built before running the demo.
./scripts/build.sh >/dev/null

set +e
./scripts/demo.sh >"${LOG_FILE}" 2>&1
STATUS=$?
set -e

if [[ ${STATUS} -ne 0 ]]; then
    echo "TLS demo run failed. Output:" >&2
    cat "${LOG_FILE}" >&2
    exit ${STATUS}
fi

if ! grep -q "Received response: Hello from TLS server!" "${LOG_FILE}"; then
    echo "Expected TLS server response not found in output." >&2
    cat "${LOG_FILE}" >&2
    exit 1
fi

if ! grep -q "TLS handshake successful" "${LOG_FILE}"; then
    echo "TLS handshake confirmation missing from output." >&2
    cat "${LOG_FILE}" >&2
    exit 1
fi

printf '%s\n' "TLS demo integration test passed."

popd >/dev/null
