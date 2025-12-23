# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Using Amazon Linux for consistency and compliance
FROM public.ecr.aws/amazonlinux/amazonlinux:latest AS uv

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Prefer the system python
ENV UV_PYTHON_PREFERENCE=only-system

# Run without updating the uv.lock file like running with `--frozen`
ENV UV_FROZEN=true

# Copy the required files first
COPY pyproject.toml uv.lock ./

# Python optimization and uv configuration
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and Python 3.13
# All packages from official Amazon Linux repositories for SBOM compliance
RUN yum update -y && \
    yum install -y \
        python3.13 \
        python3.13-pip \
        gcc \
        gcc-c++ \
        make \
        libffi-devel \
        openssl-devel \
        rust \
        cargo && \
    yum clean all

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    python3.13 -m pip install uv && \
    uv sync --python 3.13 --frozen --no-install-project --no-dev --no-editable

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --python 3.13 --frozen --no-dev --no-editable

# Make the directory just in case it doesn't exist
RUN mkdir -p /root/.local

# Using Amazon Linux for consistency and compliance
FROM public.ecr.aws/amazonlinux/amazonlinux:latest

# Place executables in the environment at the front of the path and include other binaries
ENV PATH="/app/.venv/bin:/app/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Install runtime dependencies and create application user
RUN yum update -y && \
    yum install -y \
        python3.13 \
        ca-certificates \
        shadow-utils && \
    yum clean all && \
    update-ca-trust && \
    groupadd -r app && \
    useradd -r -g app -d /app app

# Copy application artifacts from build stage
COPY --from=uv --chown=app:app /app/.venv /app/.venv

# Get healthcheck script
COPY ./docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

# Run as non-root
USER app

# Health check to monitor container status
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 CMD ["docker-healthcheck.sh"]

# Application entrypoint
ENTRYPOINT ["mcp-proxy-for-aws"]
