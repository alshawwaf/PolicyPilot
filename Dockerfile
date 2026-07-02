# Pinned to 3.12-slim for broad wheel availability inside the image.
FROM python:3.12-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Build identity, surfaced in /version + the "About PolicyPilot" menu so ops can confirm the deployed commit.
# Pass the commit at build (Dokploy -> Build Args: GIT_SHA=<sha>) to show the SHA; the build TIMESTAMP is
# always baked (no config) and changes every rebuild, so a redeploy is visible even without the SHA.
ARG GIT_SHA=dev
ENV PILOT_BUILD_SHA=$GIT_SHA
RUN date -u +"%Y-%m-%dT%H:%M:%SZ" > /srv/app/_built_at.txt

ENV PILOT_DATABASE_URL=sqlite:////data/policypilot.db
VOLUME ["/data"]
EXPOSE 8000

# Drop privileges: run as a non-root user. /data (the named volume) is created + owned by that user so the
# SQLite DB is writable on first boot. (A bind-mount to a host dir must be chowned to UID 10001 on the host.)
RUN useradd --system --uid 10001 --create-home --home-dir /home/app app \
    && mkdir -p /data && chown -R app:app /data /srv
USER app

# Dokploy/Traefik terminates TLS and routes the domain to port 8000 — no Caddy in the hosted path.
# stdlib healthcheck (slim image has no curl) so Dokploy can report container health.
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

# --proxy-headers so uvicorn honors Traefik's X-Forwarded-* (real gateway IP in the poll log).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
