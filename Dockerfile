ARG PYTHON_DEV=cgr.dev/chainguard/python@sha256:4bf7e945777010672b8ccd5d2ae2c41c91ad6d3478878347c731ae536d506bef
ARG PYTHON_RUNTIME=cgr.dev/chainguard/python@sha256:1f6779775c9f466890da563e411cb677045a6c20b6a65160eefad1deffb5012c

FROM ${PYTHON_DEV} AS builder
USER root
WORKDIR /build
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir --requirement requirements.txt \
    && /opt/venv/bin/python -m pip uninstall --yes pip setuptools wheel

FROM ${PYTHON_RUNTIME} AS runtime

FROM ${PYTHON_DEV} AS runtime-updater
USER root
COPY --from=runtime / /runtime
RUN apk --root /runtime --no-scripts add --upgrade py3-pip-wheel=26.2.1-r4

FROM scratch
COPY --from=runtime-updater /runtime /

ARG VCS_REF=unreleased
ARG SOURCE_URL=https://github.com/appolon1908/codestra-provisioning-service
ARG VERSION=unreleased
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION \
      io.codestra.python.base.repository="cgr.dev/chainguard/python" \
      io.codestra.python.base.digest="sha256:1f6779775c9f466890da563e411cb677045a6c20b6a65160eefad1deffb5012c"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app /app/app
COPY scripts /app/scripts
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8443", "--workers", "1", "--ssl-certfile", "/run/provisioning-secrets/server.crt", "--ssl-keyfile", "/run/provisioning-secrets/server.key", "--no-server-header"]
