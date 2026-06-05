FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libpq5 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /usr/sbin/nologin aegis

COPY backend/requirements.runtime.txt /tmp/requirements.runtime.txt
RUN pip install --upgrade pip \
    && pip install -r /tmp/requirements.runtime.txt

COPY backend ./backend
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

RUN chown -R aegis:aegis /app
USER aegis

EXPOSE 8000

CMD ["uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
