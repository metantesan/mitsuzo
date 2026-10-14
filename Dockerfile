# Stage 1: Builder
FROM rust:1.97-trixie AS builder

# trixie (glibc >= 2.39) is required: the prebuilt dioxus-cli `dx` binary is
# linked against a newer glibc than bookworm provides (needs GLIBC_2.39).

WORKDIR /app

# curl for the cargo-binstall installer.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-binstall
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && chmod +x /usr/local/cargo/bin/cargo-binstall

# Install the Dioxus CLI, pinned to the workspace's Dioxus version.
RUN /usr/local/cargo/bin/cargo binstall dioxus-cli --version 0.7.10 --no-confirm

# Copy project files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Accept APP_VERSION build arg
ARG APP_VERSION="dev"

# Build frontend with version
ENV BASE_URL=""
ENV APP_VERSION=${APP_VERSION}
RUN cd crates/frontend && dx build --release

# Build backend
RUN cargo build --release --locked -p backend

# Stage 2: Runner
FROM debian:trixie-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /app mitsuzo

# Copy frontend assets and binary from builder stage
COPY --from=builder /app/target/dx/mitsuzo-frontend/release/web/public ./public
COPY --from=builder /app/target/release/backend ./backend

# Runtime data lives here; owned by the unprivileged user.
RUN mkdir -p /app/database && chown -R mitsuzo:mitsuzo /app
USER mitsuzo

# Expose the port the backend listens on
EXPOSE 3030

# Set the PORT environment variable for the backend
ENV PORT=3030

# Optional: run as a restricted live demo (1 minute TTL, 5 MB max paste size)
# UNCOMMENT to enable:
# ENV MITSUZO_DEMO_MODE=1

# Optional: behind a reverse proxy, trust its forwarded client address
# UNCOMMENT to enable:
# ENV MITSUZO_TRUST_PROXY=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3030/healthz || exit 1

# Run the backend server
CMD ["./backend"]
