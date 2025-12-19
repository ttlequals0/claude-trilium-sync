FROM python:3.12-slim

LABEL maintainer="claude-trilium-sync"
LABEL description="Syncs Claude.ai conversations to Trilium Notes"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY sync.py version.py ./

# Create data directory for state persistence
RUN mkdir -p /data

# Default environment
ENV TRILIUM_URL=http://trilium:8080
ENV STATE_FILE=/data/state.json
ENV SYNC_INTERVAL=3600
ENV LOG_LEVEL=INFO

# Health check - verify we can import dependencies
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; from trilium_py.client import ETAPI" || exit 1

CMD ["python", "-u", "sync.py"]
