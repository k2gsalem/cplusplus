#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
CERT_DIR="${ROOT_DIR}/certs"
CLIENT_BIN="${BUILD_DIR}/bin/client"

if [[ ! -x "${CLIENT_BIN}" ]]; then
    echo "Client binary not found. Building project first..."
    "${ROOT_DIR}/scripts/build.sh"
fi

if [[ ! -f "${CERT_DIR}/ca.crt" ]]; then
    # The server script may already be generating certificates. Wait briefly
    # before deciding to regenerate them ourselves.
    for _ in {1..10}; do
        if [[ -f "${CERT_DIR}/ca.crt" ]]; then
            break
        fi
        sleep 0.5
    done

    if [[ ! -f "${CERT_DIR}/ca.crt" ]]; then
        echo "CA certificate missing. Generating development certificates..."
        "${ROOT_DIR}/scripts/generate_certs.sh"
    fi
fi

( cd "${ROOT_DIR}" && "${CLIENT_BIN}" )
