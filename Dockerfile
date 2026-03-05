FROM rust:1.82-bookworm AS builder
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libsqlite3-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p pqmsg-server

FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 tini && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home --home-dir /app pqmsg
COPY --from=builder /workspace/target/release/pqmsg-server /usr/local/bin/pqmsg-server
USER 10001:10001
ENV PQMSG_BIND=0.0.0.0:8080
ENV RUST_LOG=pqmsg_server=info
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/pqmsg-server"]
