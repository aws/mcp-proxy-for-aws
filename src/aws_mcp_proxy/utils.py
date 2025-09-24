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

"""Utility functions for the AWS MCP Proxy."""
import logging
import re
from src.aws_mcp_proxy.sigv4_helper import create_sigv4_client
from fastmcp.client.transports import StreamableHttpTransport
from typing import Optional
from urllib.parse import urlparse


def create_transport_with_sigv4(
    url: str, service: str, profile: Optional[str] = None
) -> StreamableHttpTransport:
    """Create a StreamableHttpTransport with SigV4 authentication.

    Args:
        url: The endpoint URL
        service: AWS service name for SigV4 signing
        profile: AWS profile to use (optional)

    Returns:
        StreamableHttpTransport instance with SigV4 authentication
    """
    return StreamableHttpTransport(
        url=url,
        httpx_client_factory=lambda **kwargs: create_sigv4_client(
            service=service, profile=profile, **kwargs
        ),
    )


def normalize_endpoint_url(endpoint: str, path: str = '/mcp') -> str:
    """Normalize endpoint URL by ensuring it has the correct path.

    Args:
        endpoint: The base endpoint URL
        path: The path to append (defaults to '/mcp')

    Returns:
        Normalized endpoint URL
    """
    endpoint_url = endpoint.rstrip('/')
    if not endpoint_url.endswith(path):
        endpoint_url += path
    return endpoint_url


def determine_service_name(endpoint: str, service: Optional[str] = None) -> str:
    """Validate and determine the service name.

    Args:
        endpoint: The endpoint URL
        service: Optional service name

    Returns:
        Validated service name

    Raises:
        ValueError: If service cannot be determined
    """
    if service:
        return service

    # Parse AWS service from endpoint URL
    parsed = urlparse(endpoint)
    hostname = parsed.hostname or ''

    # Extract service name (first part before first dot or dash)
    service_match = re.match(r'^([^.]+)', hostname)
    determined_service = service_match.group(1) if service_match else None

    if not determined_service:
        raise ValueError(
            f"Could not determine AWS service name from endpoint '{endpoint}'. "
            'Please provide the service name explicitly using --service argument.'
        )
    return determined_service
