# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

ARG TARGETPLATFORM
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++-aarch64-linux-gnu libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

COPY Cargo.toml Cargo.lock ./
COPY assets ./assets
COPY src ./src
COPY README.md ./

RUN case "$TARGETPLATFORM" in \
      "linux/amd64") rust_target="x86_64-unknown-linux-gnu" ;; \
      "linux/arm64") rust_target="aarch64-unknown-linux-gnu" ;; \
      *) echo "unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac \
    && if [ "$rust_target" = "aarch64-unknown-linux-gnu" ]; then \
         export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
                CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
                CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++; \
       fi \
    && cargo build --locked --release --target "$rust_target" --bin crosspaste-server \
    && mkdir -p /out \
    && cp "target/${rust_target}/release/crosspaste-server" /out/crosspaste-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin crosspaste \
    && mkdir -p /data \
    && chown -R crosspaste:crosspaste /data

COPY --from=builder /out/crosspaste-server /usr/local/bin/crosspaste-server

ENV CROSSPASTE_SERVER_LISTEN=0.0.0.0:39445 \
    CROSSPASTE_SERVER_DATA_DIR=/data \
    RUST_LOG=info,crosspaste_server=info

EXPOSE 39445
VOLUME ["/data"]
USER crosspaste
WORKDIR /data

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/crosspaste-server"]
