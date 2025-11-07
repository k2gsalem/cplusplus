# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN chmod +x scripts/*.sh \
    && ./scripts/generate_certs.sh \
    && ./scripts/build.sh

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cpp-tls-demo
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/build ./build
COPY --from=build /app/certs ./certs
COPY --from=build /app/include ./include
COPY --from=build /app/src ./src
COPY --from=build /app/CMakeLists.txt ./
COPY --from=build /app/README.md ./

ENV PATH="/opt/cpp-tls-demo/scripts:${PATH}"
ENV TLS_DEMO_CERT_DIR="/opt/cpp-tls-demo/certs"

EXPOSE 5555

CMD ["./scripts/demo.sh"]
