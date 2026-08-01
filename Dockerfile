# syntax=docker/dockerfile:1

# ---------- Build stage: install dependencies ----------
FROM python:3.14-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip

COPY requirements.txt ./
RUN pip install --prefix=/install -r requirements.txt

# ---------- Runtime stage: lean, non-root ----------
FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Non-root user
RUN groupadd --system aegis && useradd --system --gid aegis --create-home aegis

WORKDIR /app

# Installed dependencies from builder
COPY --from=builder /install /usr/local

# Application code only (see .dockerignore)
COPY backend ./backend
COPY config ./config

# Runtime dirs (SQLite DB, reports) owned by the app user
RUN mkdir -p /app/data /app/reports \
    && chown -R aegis:aegis /app

USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
