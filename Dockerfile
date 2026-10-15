FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Only what the web demo needs (everything else is excluded by .dockerignore)
COPY backend/ backend/
COPY contracts/ contracts/
COPY fixtures/organization/*.json fixtures/organization/
COPY webapp/ webapp/

# Run as a normal user, not root
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "uvicorn webapp.app:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header"]
