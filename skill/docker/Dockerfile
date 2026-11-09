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
# Pi's find tool runs fd with --no-require-git outside git repositories, which
# includes every snapshot. fd added that flag in 8.7.0 and Debian bookworm ships
# fd-find 8.6.0, so install the pinned upstream static build after checking it.
RUN fd_version=10.5.0 \
 && case "$(dpkg --print-architecture)" in \
      arm64) fd_target=aarch64-unknown-linux-musl \
             fd_sha256=d76c4317f7d5dba69f8a2a15856c90c777e7f0dd4e85f0de8c76de6992c374d4 ;; \
      amd64) fd_target=x86_64-unknown-linux-musl \
             fd_sha256=761c72dc8e120d85b22292063be8a796e2eeb20eb3e4f38b8fa2343ccf3514a7 ;; \
      *) echo "No pinned fd build for this architecture" >&2; exit 1 ;; \
    esac \
 && fd_dir="fd-v${fd_version}-${fd_target}" \
 && curl -fsSL --proto '=https' --retry 3 -o /tmp/fd.tar.gz \
      "https://github.com/sharkdp/fd/releases/download/v${fd_version}/${fd_dir}.tar.gz" \
 && echo "${fd_sha256}  /tmp/fd.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/fd.tar.gz -C /tmp \
      "${fd_dir}/fd" "${fd_dir}/LICENSE-MIT" "${fd_dir}/LICENSE-APACHE" \
 && install -m 0755 "/tmp/${fd_dir}/fd" /usr/local/bin/fd \
 && install -d /usr/local/share/doc/fd \
 && install -m 0644 "/tmp/${fd_dir}/LICENSE-MIT" "/tmp/${fd_dir}/LICENSE-APACHE" /usr/local/share/doc/fd/ \
 && rm -rf /tmp/fd.tar.gz "/tmp/${fd_dir}" \
 && fd --version
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
