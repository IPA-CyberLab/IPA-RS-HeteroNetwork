# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace --locked \
    && cp target/release/ipars /usr/local/bin/ipars \
    && cp target/release/iparsd /usr/local/bin/iparsd

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/heteronetwork
COPY --from=build /usr/local/bin/ipars /usr/local/bin/ipars
COPY --from=build /usr/local/bin/iparsd /usr/local/bin/iparsd
ENTRYPOINT ["/usr/local/bin/ipars"]
