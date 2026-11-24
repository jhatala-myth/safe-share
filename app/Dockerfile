# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN groupadd -g 10001 app && useradd -u 10001 -g app -r -M -s /usr/sbin/nologin app \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /install /usr/local
WORKDIR /srv
COPY --chown=root:root safeshare ./safeshare
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"]
# --no-access-log: secret IDs never land in app logs; nginx logs redacted URIs.
CMD ["uvicorn", "safeshare.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--no-access-log", "--no-server-header", "--no-date-header", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
