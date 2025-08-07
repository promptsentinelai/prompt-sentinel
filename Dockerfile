# Multi-stage Dockerfile for PromptSentinel

# Stage 1: Builder
FROM python:3.11-slim as builder

# Install UV for fast dependency installation
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml .
COPY src/ ./src/

# Install dependencies using UV
RUN uv pip install --system --no-cache .

# Stage 2: Runtime
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    mkdir -p /app && \
    chown -R sentinel:sentinel /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=sentinel:sentinel src/ ./src/
COPY --chown=sentinel:sentinel corpus/ ./corpus/

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