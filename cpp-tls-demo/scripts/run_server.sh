#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
CERT_DIR="${ROOT_DIR}/certs"
SERVER_BIN="${BUILD_DIR}/bin/server"

if [[ ! -x "${SERVER_BIN}" ]]; then
    echo "Server binary not found. Building project first..."
    "${ROOT_DIR}/scripts/build.sh"
fi

if [[ ! -f "${CERT_DIR}/server.crt" || ! -f "${CERT_DIR}/server.key" ]]; then
    echo "Server certificate or key missing. Generating development certificates..."
    "${ROOT_DIR}/scripts/generate_certs.sh"
fi

( cd "${ROOT_DIR}" && "${SERVER_BIN}" )
