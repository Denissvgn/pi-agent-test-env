# Maintainer test image: one exact Python plus Node.js for the JavaScript fixtures.
# Build natively, for example:
#   docker build -f tools/ci/Dockerfile --build-arg PYTHON_IMAGE=python:3.10-slim-bookworm \
#     -t pi-agent-ci:py3.10 tools/ci
# The suite runs offline; no package installation happens at test time.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG NODE_IMAGE=node:24-bookworm-slim
FROM ${NODE_IMAGE} AS node
FROM ${PYTHON_IMAGE}
COPY --from=node /usr/local/bin/node /usr/local/bin/node
RUN node --version && python3 --version
