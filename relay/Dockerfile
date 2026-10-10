# Aegis dumb relay — stdlib-only Python, no dependencies to install.
FROM python:3.12-slim

WORKDIR /srv/aegis
COPY relay.py .

# Drop privileges: the process holds no secrets and needs none.
RUN useradd -r -s /usr/sbin/nologin aegis \
    && chown -R aegis:aegis /srv/aegis
USER aegis

# The relay speaks plain WebSocket; terminate TLS in front of it
# (Caddy sidecar, fly.io/railway edge, etc.).
ENV AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8765
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; socket.create_connection(('127.0.0.1', 8765), timeout=4).close()"

CMD ["python3", "relay.py"]
