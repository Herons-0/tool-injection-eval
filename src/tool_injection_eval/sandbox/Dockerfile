# Sandbox for the tool-injection eval.
#
# The agent's tools only list, read and write files here, so the image needs
# nothing beyond a shell and coreutils: no Python, no network tools.
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN useradd --create-home agent \
 && mkdir -p /workspace \
 && chown agent:agent /workspace

USER agent
WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
