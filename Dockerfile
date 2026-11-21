FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpcap0.8 libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY requirements-v4.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data /app/reports
EXPOSE 8080
CMD ["uvicorn", "webapp:app", "--host", "0.0.0.0", "--port", "8080"]