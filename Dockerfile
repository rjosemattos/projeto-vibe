FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROMPT_SANITIZER_AUTH_ENABLED=true \
    PROMPT_SANITIZER_HOST=0.0.0.0 \
    PROMPT_SANITIZER_TRUST_PROXY_HEADERS=true \
    PROMPT_SANITIZER_DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt .
# Desktop-only packages (tray icon) are not needed in the server image
RUN grep -viE '^(pillow|pystray)' requirements.txt > req-server.txt \
    && pip install --no-cache-dir -r req-server.txt

COPY app ./app
COPY run_server.py manage_users.py ./

RUN useradd --system --uid 10001 --no-create-home sanitizer \
    && mkdir /data && chown sanitizer /data
USER sanitizer
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
