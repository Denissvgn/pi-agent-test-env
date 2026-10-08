# Build on the developer HOST. Never install OS packages in the read-only runtime.
ARG BASE_IMAGE=node:24-bookworm-slim
FROM ${BASE_IMAGE}
ARG PI_VERSION
ARG WITH_BROWSER=0
ARG EXTRA_APT_PACKAGES=""
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates git ripgrep curl jq file python3 python3-venv \
      build-essential pkg-config ${EXTRA_APT_PACKAGES} \
 && if [ "$WITH_BROWSER" = "1" ]; then \
      apt-get install -y --no-install-recommends chromium chromium-sandbox fonts-liberation; \
    fi \
 && rm -rf /var/lib/apt/lists/*
# Explicit caller-selected version: never silently replace it or use latest.
# references/PI-COMPATIBILITY.md records the source-inspected 0.87.1 candidate;
# installed Node/Pi/image identities and native execution must be verified.
# No default PI_VERSION is set here: a different release needs its own contract.
RUN test -n "$PI_VERSION" \
 && npm install --global --ignore-scripts "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && pi --version \
 && npm cache clean --force
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    CHROME_BIN=/usr/bin/chromium \
    PYTHONDONTWRITEBYTECODE=1
LABEL org.pi-agentic-development.schema="2"
WORKDIR /workspace
USER node
ENTRYPOINT ["pi"]
