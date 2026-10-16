# ─────────────────────────────────────────────────────────────────
# FortiDoc Dev — Docker build for deployment
# ─────────────────────────────────────────────────────────────────
FROM python:3.12-alpine

RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && apk del .build-deps

COPY *.py .
COPY templates/ templates/
COPY static/ static/

RUN adduser -D -h /app appuser && chown -R appuser:appuser /app
# Pre-create the settings volume dir (named volume first-mount inherits
# ownership from the image), so appuser can write settings.json.
RUN mkdir -p /app/settings && chown -R appuser:appuser /app/settings
USER appuser

ENV PORT=8080
ENV GUNICORN_WORKERS=4

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

CMD gunicorn --workers ${GUNICORN_WORKERS} \
             --bind 0.0.0.0:${PORT} \
             --access-logfile - \
             --error-logfile - \
             app:app
