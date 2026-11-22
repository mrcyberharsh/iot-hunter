FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/backend \
    IOT_HUNTER_CONFIG=/app/backend/config.yaml \
    IOT_HUNTER_DATA=/app/data
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpcap0.8 libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
# Bind-mounted data and reports must be writable by UID 10001.
RUN useradd --system --uid 10001 --no-create-home iothunter \
    && mkdir -p /app/data /app/reports \
    && chown -R iothunter /app/data /app/reports
USER iothunter
EXPOSE 8080
CMD ["uvicorn", "webapp:app", "--app-dir", "/app/backend", "--host", "0.0.0.0", "--port", "8080"]
