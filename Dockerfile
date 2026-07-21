# Stage 1: Builder
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies for rocksdb-sys and cargo-binstall
RUN apt-get update && apt-get install -y clang libclang-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-binstall
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && chmod +x /usr/local/cargo/bin/cargo-binstall

# Install Dioxus CLI using cargo binstall
RUN /usr/local/cargo/bin/cargo binstall dioxus-cli --no-confirm

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
RUN cargo build --release -p backend

# Stage 2: Runner
FROM debian:stable

WORKDIR /app

# Copy frontend assets and binary from builder stage
COPY --from=builder /app/target/dx/mitsuzo-frontend/release/web/public ./public
COPY --from=builder /app/target/release/backend ./backend

# Expose the port the backend listens on
EXPOSE 3030

# Set the PORT environment variable for the backend
ENV PORT=3030

# Run the backend server
CMD ["./backend"]