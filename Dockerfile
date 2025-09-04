# ---------- Stage 1: build Rust binary ----------
FROM rust:1.85-slim AS rust-builder
WORKDIR /app
# System deps (openssl is a safe default for reqwest builds)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Prime cargo cache first
COPY Cargo.toml Cargo.lock ./
# If you have a src/ dir, copy a dummy to warm cache; else skip
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && cargo build --release || true
# Now copy real sources and build
COPY src ./src
RUN cargo build --release

# ---------- Stage 2: runtime (Python + binary) ----------
FROM python:3.11-slim
WORKDIR /app

# System deps just in case
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the Rust binary
COPY --from=rust-builder /app/target/release/pleb_scan /app/bin/pleb_scan

RUN chmod +x /app/bin/pleb_scan
ENV PLEBSCAN_BIN=/app/bin/pleb_scan

# Copy Flask app
# If your Flask UI lives in flask-ui/, keep these paths.
COPY flask-ui/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY flask-ui/app.py /app/app.py
COPY flask-ui/templates /app/templates
COPY flask-ui/static /app/static

# Env expected by app.py
ENV PLEBSCAN_BIN=/app/bin/pleb_scan \
    PORT=10000 \
    PYTHONUNBUFFERED=1

EXPOSE 10000
# Gunicorn entrypoint
CMD ["gunicorn", "-w", "2", "-k", "gthread", "-b", "0.0.0.0:10000", "app:app", "--timeout", "120"]
