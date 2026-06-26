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

# dependabot should continue to update this to the latest hash.
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:a450a74bfebfa936e7106d79c8b4b4dd0ca891c790513f84624da02a0e5531db AS uv

RUN dnf install -y shadow-utils python3.13 && \
    dnf clean all

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_PREFERENCE=only-managed
ENV UV_FROZEN=true
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml uv.lock uv-requirements.txt ./

RUN --mount=type=cache,target=/root/.cache/uv \
    python3.13 -m ensurepip && \
    python3.13 -m pip install --require-hashes --requirement uv-requirements.txt --no-cache-dir && \
    uv sync --python 3.13 --frozen --no-install-project --no-dev --no-editable

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --python 3.13 --frozen --no-dev --no-editable

RUN mkdir -p /root/.local

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:a450a74bfebfa936e7106d79c8b4b4dd0ca891c790513f84624da02a0e5531db

ENV PATH="/app/.venv/bin:$PATH:/usr/sbin" \
    PYTHONUNBUFFERED=1

RUN dnf install -y shadow-utils procps lsof ca-certificates && \
    dnf clean all && \
    update-ca-trust && \
    groupadd --force --system app && \
    useradd app -g app -d /app && \
    chmod o+x /root

COPY --from=uv --chown=app:app /root/.local /root/.local
COPY --from=uv --chown=app:app /app/.venv /app/.venv

COPY ./docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

USER app

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 CMD ["docker-healthcheck.sh"]
ENTRYPOINT ["mcp-proxy-for-aws"]
