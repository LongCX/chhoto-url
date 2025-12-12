# SPDX-FileCopyrightText: 2023 Sayantan Santra <sayantan.santra689@gmail.com>
# SPDX-License-Identifier: MIT

FROM docker.io/lukemathwalker/cargo-chef:latest-rust-slim AS chef
WORKDIR /chhoto-url

FROM chef AS planner
COPY ./actix/Cargo.toml ./actix/Cargo.lock ./
COPY ./actix/src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG target=x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools build-essential pkg-config libssl-dev ca-certificates
RUN rustup target add $target

COPY --from=planner /chhoto-url/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer
RUN cargo chef cook --release --target=$target --recipe-path recipe.json

COPY ./actix/Cargo.toml ./actix/Cargo.lock ./
COPY ./actix/src ./src
# Build application
RUN cargo build --release --target=$target --locked --bin chhoto-url
RUN cp /chhoto-url/target/$target/release/chhoto-url /chhoto-url/release

FROM alpine:latest AS tz
RUN apk add --no-cache tzdata
RUN mkdir /db

# Health
FROM 11notes/distroless:localhealth AS distroless-localhealth

FROM scratch
COPY --chown=65532:65532 --from=tz /db /db
COPY --chown=65532:65532 --from=tz /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime
COPY --chown=65532:65532 --from=builder /chhoto-url/release /app/chhoto-url
COPY --chown=65532:65532 ./resources /app/resources
COPY --chown=65532:65532 --from=distroless-localhealth / /

VOLUME ["/db"]

EXPOSE 4567

HEALTHCHECK --interval=120s --timeout=2s --start-period=5s \
  CMD ["/usr/local/bin/localhealth", "http://127.0.0.1:4567/"]

USER 65532:65532

CMD ["/app/chhoto-url"]
