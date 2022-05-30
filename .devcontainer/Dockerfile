# See here for image contents: https://github.com/microsoft/vscode-dev-containers/blob/v0.163.0/containers/python-3/.devcontainer/base.Dockerfile
ARG VARIANT="3"
FROM mcr.microsoft.com/vscode/devcontainers/python:0-${VARIANT}

# Install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    build-essential \
    libsasl2-dev \
    libldap2-dev \
    libssl-dev \
    libffi-dev \
    xmlsec1