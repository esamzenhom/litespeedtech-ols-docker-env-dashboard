FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN apk add --no-cache bash curl
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates ./templates
COPY static ./static
RUN mkdir -p /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --start-period=8s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=8", "--timeout=900", "app:app"]
