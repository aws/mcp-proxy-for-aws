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

"""Utility functions for the MCP Proxy for AWS."""

import argparse
import httpx
import logging
import os
import re
from fastmcp.client.transports import StreamableHttpTransport
from mcp_proxy_for_aws.sigv4_helper import create_sigv4_client
from typing import Dict, Optional
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


def create_transport_with_sigv4(
    url: str,
    service: str,
    region: str,
    custom_timeout: httpx.Timeout,
    profile: Optional[str] = None,
) -> StreamableHttpTransport:
    """Create a StreamableHttpTransport with SigV4 authentication.

    Args:
        url: The endpoint URL
        service: AWS service name for SigV4 signing
        region: AWS region to use
        custom_timeout: httpx.Timeout used to connect to the endpoint
        profile: AWS profile to use (optional)


    Returns:
        StreamableHttpTransport instance with SigV4 authentication
    """

    def client_factory(
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[httpx.Timeout] = None,
        auth: Optional[httpx.Auth] = None,
    ) -> httpx.AsyncClient:
        return create_sigv4_client(
            service=service,
            profile=profile,
            region=region,
            headers=headers,
            timeout=custom_timeout,
            metadata={'AWS_REGION': region},
            auth=auth,
        )

    return StreamableHttpTransport(
        url=url,
        httpx_client_factory=client_factory,
    )


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


def determine_aws_region(endpoint: str, region: Optional[str]) -> str:
    """Validate and determine the AWS region.

    Args:
        endpoint: The endpoint URL
        region: Optional region name

    Returns:
        Validated AWS region

    Raises:
        ValueError: If region cannot be determined
    """
    if region:
        logger.debug('Region determined through explicit parameter')
        return region

    # Parse AWS region from endpoint URL
    parsed = urlparse(endpoint)
    hostname = parsed.hostname or ''

    # Extract region name (pattern: service.region.api.aws or service-name.region.api.aws)
    region_match = re.search(r'\.([a-z0-9-]+)\.api\.aws', hostname)
    if region_match:
        logger.debug('Region determined through endpoint URL')
        return region_match.group(1)

    environment_region = os.getenv('AWS_REGION')
    if environment_region:
        logger.debug('Region determined through environment variable')
        return environment_region

    raise ValueError(
        f"Could not determine AWS region from endpoint '{endpoint}' or from environment variable AWS_REGION. "
        'Please provide the region explicitly using --region argument.'
    )


def within_range(min_value: float, max_value: Optional[float] = None):
    """Factory function to create range validators.

    Args:
        min_value: Minimum value
        max_value: Maximum value


    Returns:
        The argparse validator function

    Raises:
        argparse.ArgumentTypeError: If min and max are not within range
    """

    def validator(value):
        try:
            fvalue = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not a valid integer")

        if min_value is not None and fvalue < min_value:
            raise argparse.ArgumentTypeError(f"'{value}' must be >= {min_value}")

        if max_value is not None and fvalue > max_value:
            raise argparse.ArgumentTypeError(f"'{value}' must be <= {max_value}")

        return fvalue

    return validator
