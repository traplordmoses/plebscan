# ---------- Stage 1: build Rust binary ----------
FROM rust:1.85-slim AS rust-builder
WORKDIR /app

# System deps (openssl headers for reqwest w/ native-tls)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# 1) Cache dependencies without producing a dummy binary
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch

# 2) Build the real sources
COPY src ./src
# Optional cache-buster: pass a different GIT_SHA to force rebuild if Render is too sticky
ARG GIT_SHA=dev
RUN echo "Building commit $GIT_SHA" && cargo build --release --locked --bin pleb_scan

# ---------- Stage 2: runtime (Python + binary) ----------
FROM python:3.11-slim
WORKDIR /app

# Runtime deps (openssl runtime + certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the Rust binary
COPY --from=rust-builder /app/target/release/pleb_scan /app/bin/pleb_scan
RUN chmod +x /app/bin/pleb_scan

# Flask app deps
COPY flask-ui/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# App code
COPY flask-ui/app.py /app/app.py
COPY flask-ui/templates /app/templates
COPY flask-ui/static /app/static

# Env expected by app.py
ENV PLEBSCAN_BIN=/app/bin/pleb_scan \
    PYTHONUNBUFFERED=1 \
    PORT=10000

EXPOSE 10000
CMD ["gunicorn", "-w", "2", "-k", "gthread", "-b", "0.0.0.0:10000", "app:app", "--timeout", "120"]
