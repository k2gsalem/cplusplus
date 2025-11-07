# Build, Deployment, and Operations Guide

## Overview

The C++ TLS Demo is a minimal client/server pair that demonstrates how to establish
mutually authenticated TLS sessions using OpenSSL. The server listens on TCP port 5555
and serves a single connection at a time. During a run the two programs:

1. Initialize the OpenSSL library and load X.509 certificates.
2. Perform a TLS handshake where the client validates the server certificate against a
   development certificate authority.
3. Exchange a short greeting payload and log handshake details to standard output.
4. Tear down the TLS session and exit.

The project is intentionally small so that the focus stays on the mechanics of bootstrapping
TLS inside a native service.

## Local Development Workflow

### Prerequisites

Install the following packages on your development machine:

- `cmake`
- `g++` (or any C++17-capable compiler)
- `make`
- `libssl-dev`
- `bash`

### Build the Binaries

```bash
cd cpp-tls-demo
./scripts/build.sh
```

The compiled `server` and `client` executables are placed in `build/bin/`.

### Generate Development Certificates

```bash
cd cpp-tls-demo
./scripts/generate_certs.sh
```

This script creates a local certificate authority (`certs/ca.crt`) and a server certificate
(`certs/server.crt`). Both scripts used to launch the binaries depend on these files.

### Run the Applications

Open two terminals and start the server first:

```bash
cd cpp-tls-demo
./scripts/run_server.sh
```

Launch the client in another terminal:

```bash
cd cpp-tls-demo
./scripts/run_client.sh
```

The `scripts/demo.sh` helper can orchestrate the interaction from a single terminal if you
prefer a hands-off experience:

```bash
cd cpp-tls-demo
./scripts/demo.sh
```

Sample output highlights the TLS handshake, prints the subject of the server certificate,
and shows the greeting exchanged across the encrypted channel.

## Container Image

A multi-stage Dockerfile is provided to create a portable runtime that contains pre-built
binaries and the generated development certificates.

### Build the Image

From the repository root:

```bash
docker build -t cpp-tls-demo -f cpp-tls-demo/Dockerfile cpp-tls-demo
```

The image contains both the client and server executables plus all project scripts.

### Run the Demo in a Container

The default container command executes `scripts/demo.sh`, which launches the server in the
background, runs the client, and reports the client exit code. Expose the server port if you
want to observe the listener from outside the container:

```bash
docker run --rm -it -p 5555:5555 cpp-tls-demo
```

To run the server or client individually, override the command when you start the container:

```bash
# Server
docker run --rm -it -p 5555:5555 cpp-tls-demo ./scripts/run_server.sh

# Client (expects a server listening on the Docker host at port 5555)
docker run --rm -it --network host cpp-tls-demo ./scripts/run_client.sh
```

If host networking is not available on your platform, start a second container on the
same user-defined Docker network instead:

```bash
docker network create tls-demo

docker run --rm -d --name tls-server --network tls-demo -p 5555:5555 cpp-tls-demo ./scripts/run_server.sh

docker run --rm --network tls-demo cpp-tls-demo ./scripts/run_client.sh
```

### Persisting or Replacing Certificates

The bundled certificates are generated during the image build. For production-style
experiments you can mount a host directory at `/opt/cpp-tls-demo/certs` to provide your
own credentials:

```bash
docker run --rm -it -p 5555:5555 \
  -v "$(pwd)/my-certs:/opt/cpp-tls-demo/certs" \
  cpp-tls-demo ./scripts/run_server.sh
```

Ensure the mounted directory contains `ca.crt`, `server.crt`, and `server.key` files.

## Deployment Considerations

- The server is synchronous and handles one client at a time; replicate containers or
  extend the implementation for concurrent clients before using it in production scenarios.
- Private keys generated for the demo are not password protected. Replace them with
  appropriately secured credentials for any real deployment.
- Logs are written to standard output so they integrate naturally with container platforms
  that collect stdout/stderr.
- Because the client expects to validate the server certificate, keep the CA certificate
  aligned between deployments.

## Troubleshooting

- **Connection refused:** Ensure port 5555 is exposed and the server container is running.
- **Certificate verification errors:** Regenerate the certificates (`./scripts/generate_certs.sh`) or
  ensure the client is using the same CA certificate as the server.
- **OpenSSL library errors inside Docker:** Confirm the host CPU supports the instruction
  set required by the base image (Ubuntu 22.04) and rebuild if necessary.
