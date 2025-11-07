#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"

"${ROOT_DIR}/scripts/run_server.sh" &
SERVER_PID=$!

# Give the server a moment to start listening and finish generating certificates.
sleep 1

for _ in {1..10}; do
    if [[ -f "${CERT_DIR}/ca.crt" && -f "${CERT_DIR}/server.crt" ]]; then
        break
    fi
    sleep 0.5
done

set +e
"${ROOT_DIR}/scripts/run_client.sh"
CLIENT_STATUS=$?
set -e

wait ${SERVER_PID} || true

exit ${CLIENT_STATUS}
