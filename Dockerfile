FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --no-create-home --home-dir /nonexistent provisioning
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /app/requirements.txt
COPY app /app/app
COPY scripts /app/scripts
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["python", "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8443", "--workers", "1", "--ssl-certfile", "/run/provisioning-secrets/server.crt", "--ssl-keyfile", "/run/provisioning-secrets/server.key", "--no-server-header"]
