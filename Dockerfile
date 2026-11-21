FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpcap0.8 libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run as an unprivileged user. If you bind-mount ./data and ./reports from the
# host, make them writable for UID 10001 (e.g. `sudo chown -R 10001 data reports`).
RUN useradd --system --uid 10001 --no-create-home iothunter \
    && mkdir -p /app/data /app/reports \
    && chown -R iothunter /app/data /app/reports
USER iothunter
EXPOSE 8080
CMD ["uvicorn", "webapp:app", "--host", "0.0.0.0", "--port", "8080"]
