FROM docker.io/library/rust:1.90.0-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake libssl-dev libsqlite3-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --bin hbbs && cp /src/target/release/hbbs /tmp/hbbs

FROM docker.io/library/debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/hbbs /usr/local/bin/hbbs
WORKDIR /data
EXPOSE 21115 21116 21116/udp
ENTRYPOINT ["/usr/local/bin/hbbs"]
