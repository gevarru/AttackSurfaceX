FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/gevarru/AttackSurfaceX"
LABEL org.opencontainers.image.description="Safe, non-destructive attack surface scanner"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY asx ./asx
RUN pip install --no-cache-dir . && useradd -m asx
USER asx

ENTRYPOINT ["asx"]
CMD ["--help"]
