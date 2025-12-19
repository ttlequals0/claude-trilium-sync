FROM python:3.12-slim

LABEL maintainer="claude-trilium-sync"
LABEL description="Syncs Claude.ai conversations to Trilium Notes using Playwright"

# Install Playwright system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libatspi2.0-0 \
    libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium

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
    CMD python -c "import httpx; from trilium_py.client import ETAPI; from playwright.async_api import async_playwright" || exit 1

CMD ["python", "-u", "sync.py"]
