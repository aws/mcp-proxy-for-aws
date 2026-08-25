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
FROM public.ecr.aws/amazonlinux/amazonlinux:latest

# Python optimization
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install runtime dependencies and create application user
RUN yum update -y && \
    yum install -y \
        python3.13 \
        python3.13-pip \
        ca-certificates \
        shadow-utils \
        lsof && \
    yum clean all && \
    update-ca-trust && \
    groupadd -r app && \
    useradd -r -g app -d /app app

# Install mcp-proxy-for-aws from PyPI
RUN python3.13 -m pip install mcp-proxy-for-aws

# Get healthcheck script
COPY ./docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

# Run as non-root
USER app

# Health check to monitor container status
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 CMD ["docker-healthcheck.sh"]

# Application entrypoint
ENTRYPOINT ["mcp-proxy-for-aws"]
