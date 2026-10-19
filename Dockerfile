FROM python:3.11-slim AS base

LABEL maintainer="mrhenrike <henrique.santos@uniaogeek.com.br>"
LABEL org.opencontainers.image.source="https://github.com/mrhenrike/ADXPL-Forge"
LABEL org.opencontainers.image.description="ADXPL: Active Directory exploitation framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libkrb5-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash xpluser

WORKDIR /opt/adxpl

COPY pyproject.toml README.md LICENSE ./
COPY adxpl/ adxpl/

RUN pip install --no-cache-dir ".[dev]"

USER xpluser

ENTRYPOINT ["adxpl"]
CMD ["--help"]
