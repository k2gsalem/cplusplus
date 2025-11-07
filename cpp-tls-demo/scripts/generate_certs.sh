#!/usr/bin/env bash
set -euo pipefail

# This script generates a local certificate authority (CA) and uses it to
# sign a server certificate suitable for localhost development.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"

mkdir -p "${CERT_DIR}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"
SERVER_EXT="${CERT_DIR}/server.ext"

if [[ -f "${CA_KEY}" || -f "${SERVER_KEY}" ]]; then
    echo "Certificates already exist. Remove the certs directory or individual files if you want to regenerate them." >&2
    exit 1
fi

openssl genrsa -out "${CA_KEY}" 4096
openssl req -x509 -new -nodes -key "${CA_KEY}" \
    -sha256 -days 825 -out "${CA_CERT}" \
    -subj "/C=US/ST=State/L=City/O=cpp-tls-demo/OU=Education/CN=cpp-tls-demo CA"

openssl genrsa -out "${SERVER_KEY}" 2048
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
    -subj "/C=US/ST=State/L=City/O=cpp-tls-demo/OU=Education/CN=localhost"

cat > "${SERVER_EXT}" <<EOT
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOT

openssl x509 -req -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SERVER_CERT}" -days 365 -sha256 \
    -extfile "${SERVER_EXT}"

rm -f "${SERVER_CSR}" "${SERVER_EXT}" "${CERT_DIR}/ca.srl"
chmod 600 "${CA_KEY}" "${SERVER_KEY}"

cat <<EOM
Generated the following files in ${CERT_DIR}:
  - ca.crt  (certificate authority certificate to trust on clients)
  - ca.key  (private key for the certificate authority)
  - server.crt (server certificate signed by the CA)
  - server.key (server private key)
EOM
