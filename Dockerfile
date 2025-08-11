# Multi-stage Dockerfile for PromptSentinel - Alpine Edition
# This Alpine-based image has significantly fewer vulnerabilities

# Stage 1: Builder
FROM python:3.13-alpine as builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers \
    python3-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    build-base

# Install UV for fast dependency installation
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml .
COPY src/ ./src/

# Install dependencies using UV
RUN uv pip install --system --no-cache .

# Stage 2: Runtime
FROM python:3.13-alpine

# Install runtime dependencies only
RUN apk add --no-cache \
    curl \
    libgcc \
    libstdc++ \
    libgomp \
    && rm -rf /var/cache/apk/*

# Create non-root user with specific UID
RUN adduser -D -u 1000 -h /app sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code with correct ownership
COPY --chown=sentinel:sentinel src/ ./src/
COPY --chown=sentinel:sentinel corpus/ ./corpus/

# Create necessary directories
RUN mkdir -p /app/config && \
    chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Set environment variables
ENV PYTHONPATH=/app/src:$PYTHONPATH \
    PYTHONUNBUFFERED=1 \
    API_HOST=0.0.0.0 \
    API_PORT=8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run the application
CMD ["python", "-m", "uvicorn", "prompt_sentinel.main:app", "--host", "0.0.0.0", "--port", "8080"]