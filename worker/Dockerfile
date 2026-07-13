FROM python:3.12.11-slim-bookworm

ARG DENO_VERSION=2.9.2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl ffmpeg unzip \
    && curl -fsSLo /tmp/deno.zip "https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-x86_64-unknown-linux-gnu.zip" \
    && unzip /tmp/deno.zip -d /usr/local/bin \
    && rm -f /tmp/deno.zip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin worker

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt
COPY --chown=worker:worker main.py .

USER worker
CMD ["python", "main.py"]
