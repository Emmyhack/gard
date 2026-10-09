# Gard fleet server image. Build from the repository root:
#   docker build -t gard .
# Run (persist the fleet directory and policy with volumes):
#   docker run -p 8787:8787 -v gard-fleet:/data/fleet -v gard-home:/data/home \
#     -e GARD_FLEET_TOKEN=change-me gard
#
# Terminate TLS in front of this container; the server speaks plain HTTP.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p gard

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --home-dir /data/home gard \
    && mkdir -p /data/fleet \
    && chown -R gard:gard /data
COPY --from=build /src/target/release/gard /usr/local/bin/gard
USER gard
ENV GARD_DATA_DIR=/data/home/.gard
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["sh", "-c", "wget -qO- http://127.0.0.1:8787/healthz | grep -q ok"]
# The token is required because the server binds beyond localhost inside
# the container network. Supply it with -e GARD_FLEET_TOKEN=...
ENTRYPOINT ["sh", "-c", "exec gard fleet serve --dir /data/fleet --bind 0.0.0.0 --port 8787 --token \"$GARD_FLEET_TOKEN\""]
