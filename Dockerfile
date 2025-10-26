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

FROM alpine AS tmp
RUN mkdir /db

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --chown=nonroot:nonroot --from=tmp /db /db
COPY --chown=nonroot:nonroot --from=builder /chhoto-url/release /app/chhoto-url
COPY --chown=nonroot:nonroot ./resources /app/resources
WORKDIR /app

USER nonroot

VOLUME ["/db"]
ENV TZ=Asia/Ho_Chi_Minh

CMD ["/app/chhoto-url"]
