FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin dlp
COPY --chown=dlp:dlp main.py .
USER dlp
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
