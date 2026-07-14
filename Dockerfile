# ---------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies (pkg-config and libssl are common for Rust crypto/networking)
RUN apt-get update && apt-get install -y pkg-config libssl-dev

# Create a new empty shell project
WORKDIR /usr/src/axiom_trade_bot

COPY . .

# Build the bot for release
RUN cargo build --release

# ---------------------------------------------------
# Stage 2: Runtime Environment
# ---------------------------------------------------
FROM debian:bookworm-slim

# Install runtime dependencies
# ca-certificates: Required for HTTPS requests to Telegram API and Solana RPC
# sqlite3: Useful if you ever need to SSH into the Railway container to debug the DB
RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/axiom_trade_bot/target/release/axiom_trade_bot /app/

# Copy the assets folder (required for the solana_logo.png)
COPY assets /app/assets

# Set environment variables
ENV RUST_LOG=info

# Ensure the binary has execution permissions
RUN chmod +x /app/axiom_trade_bot

# Command to run the bot
CMD ["./axiom_trade_bot"]
