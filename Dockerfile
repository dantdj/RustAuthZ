# Lightly adapted from https://stackoverflow.com/a/64141061
# Just added some extra copying for the configuration.yaml

FROM ekidd/rust-musl-builder:stable AS builder

COPY . .
RUN --mount=type=cache,target=/home/rust/.cargo/git \
    --mount=type=cache,target=/home/rust/.cargo/registry \
    --mount=type=cache,sharing=private,target=/home/rust/src/target \
    sudo chown -R rust: target /home/rust/.cargo && \
    cargo build --release && \
    # Copy executable out of the cache so it is available in the final image.
    cp target/x86_64-unknown-linux-musl/release/rust_authz ./rust_authz

FROM alpine
COPY --from=builder /home/rust/src/rust_authz .
COPY --from=builder /home/rust/src/configuration.yaml .
USER 1000
CMD ["./rust_authz"]