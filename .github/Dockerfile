FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install build deps and pip
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip

# If you use requirements.txt
COPY requirements.txt ./
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi

# Copy project
COPY . .

# Expose port (adjust if needed)
EXPOSE 8000

# Default command: adjust to your actual app entrypoint
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
