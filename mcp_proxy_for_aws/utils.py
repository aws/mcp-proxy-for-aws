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
from fastmcp.client.transports import StreamableHttpTransport
from mcp_proxy_for_aws.sigv4_helper import create_sigv4_client
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


def create_transport_with_sigv4(
    url: str,
    service: str,
    region: str,
    metadata: Dict[str, Any],
    custom_timeout: httpx.Timeout,
    profile: Optional[str] = None,
) -> StreamableHttpTransport:
    """Create a StreamableHttpTransport with SigV4 authentication.

    Args:
        url: The endpoint URL
        service: AWS service name for SigV4 signing
        region: AWS region to use
        metadata: Metadata dictionary to inject into MCP requests
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
            metadata=metadata,
            auth=auth,
        )

    return StreamableHttpTransport(
        url=url,
        httpx_client_factory=client_factory,
    )


def get_service_name_and_region_from_endpoint(endpoint: str) -> Tuple[str, str]:
    """Extract service name and region from an endpoint URL.

    Args:
        endpoint: The endpoint URL to parse

    Returns:
        Tuple of (service_name, region). Either value may be empty string if not found.

    Notes:
        - Matches bedrock-agentcore endpoints (gateway and runtime)
        - Matches AWS API Gateway endpoints (service.region.api.aws)
        - Falls back to extracting first hostname segment as service name
    """
    # Parse AWS service from endpoint URL
    parsed = urlparse(endpoint)
    hostname = parsed.hostname or ''
    match hostname.split('.'):
        case [*_, 'bedrock-agentcore', region, 'amazonaws', 'com']:
            return 'bedrock-agentcore', region  # gateway and runtime
        case [service, region, 'api', 'aws']:
            return service, region
        case [service, *_]:
            # Fallback: extract first segment as service name
            return service, ''
        case _:
            logger.warning('Could not parse endpoint, no hostname found')
            return '', ''


def determine_service_name(endpoint: str, service: Optional[str] = None) -> str:
    """Validate and determine the service name and possibly region from an endpoint.

    Args:
        endpoint: The endpoint URL
        service: Optional service name

    Returns:
        Validated service name
        Validated region

    Raises:
        ValueError: If service cannot be determined
    """
    if service:
        return service

    logger.info('Resolving service name')
    endpoint_service, _ = get_service_name_and_region_from_endpoint(endpoint)
    determined_service = service or endpoint_service

    if not determined_service:
        raise ValueError(
            f"Could not determine AWS service name and region from endpoint '{endpoint}' and they were not provided."
            'Please provide the service name explicitly using --service argument and the region via --region argument.'
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
    _, endpoint_region = get_service_name_and_region_from_endpoint(endpoint)
    if endpoint_region:
        logger.debug('Region determined through endpoint URL')
        return endpoint_region

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
