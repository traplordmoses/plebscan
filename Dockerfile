# ---------- Stage 1: build Rust binary ----------
FROM rust:1.85-slim AS rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy manifests AND sources, then build (simple, fewer cache tricks)
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# ---------- Stage 2: runtime (Python + binary) ----------
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the Rust binary
COPY --from=rust-builder /app/target/release/pleb_scan /app/bin/pleb_scan
RUN chmod +x /app/bin/pleb_scan

# Env for the Flask app
ENV PLEBSCAN_BIN=/app/bin/pleb_scan \
    PORT=10000 \
    PYTHONUNBUFFERED=1

# Python deps + app
COPY flask-ui/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY flask-ui/app.py /app/app.py
COPY flask-ui/templates /app/templates
COPY flask-ui/static /app/static

EXPOSE 10000
CMD ["gunicorn","-w","2","-k","gthread","-b","0.0.0.0:10000","app:app","--timeout","120"]
