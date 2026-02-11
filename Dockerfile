# MIMF Service Image
# Security notes:
# - Runs as non-root.
# - No secrets baked into image; provide MIMF_API_KEYS via env/secret.
# Complexity: build steps are linear in project size.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . /app

# Install package with API extras
RUN pip install --no-cache-dir ".[api]"

# Create non-root user
RUN useradd -m -u 10001 mimf && mkdir -p /data && chown -R mimf:mimf /data
USER mimf

ENV MIMF_DB_PATH=/data/mimf_runtime.db \
    MIMF_REQUIRE_AUTH=1 \
    MIMF_MAX_UPLOAD_BYTES=26214400 \
    MIMF_RATE_LIMIT_RPM=120 \
    MIMF_RATE_LIMIT_BURST=120

EXPOSE 8080

# Use the env-driven app factory
CMD ["uvicorn", "mimf.api.server:app", "--host", "0.0.0.0", "--port", "8080"]
