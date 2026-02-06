# Mock Beacon Node for Integration Testing
# This is a placeholder - implement the mock beacon node in Rust or use a scripted solution

FROM rust:1.75-slim-bookworm AS builder

WORKDIR /build
COPY . .

# Build if Cargo.toml exists, otherwise create a simple HTTP server
RUN if [ -f Cargo.toml ]; then cargo build --release; fi

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install simple HTTP server for mock responses
RUN pip3 install --break-system-packages flask

WORKDIR /app

# Copy mock server script
COPY mock_server.py /app/

EXPOSE 5052

CMD ["python3", "/app/mock_server.py"]
