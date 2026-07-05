FROM rust:1.80-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/ipars
COPY --from=build /src/target/release/ipars /usr/local/bin/ipars
COPY --from=build /src/target/release/iparsd /usr/local/bin/iparsd
ENTRYPOINT ["/usr/local/bin/ipars"]
