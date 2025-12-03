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

"""MCP Proxy for AWS Server entry point.

This server provides a unified interface to backend servers by:
1. Using JSON-RPC calls to MCP endpoints for a single backend server
2. Loading tools from configured backend servers
3. Registering tools with prefixed names
4. Providing tool listing functionality through the MCP protocol
5. Supporting tool refresh
"""

import asyncio
import httpx
import logging
from fastmcp.server.middleware.error_handling import RetryMiddleware
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.server.server import FastMCP
from mcp_proxy_for_aws.cli import parse_args
from mcp_proxy_for_aws.logging_config import configure_logging
from mcp_proxy_for_aws.middleware.initialize_middleware import InitializeMiddleware
from mcp_proxy_for_aws.middleware.tool_filter import ToolFilteringMiddleware
from mcp_proxy_for_aws.proxy import AWSMCPProxy, AWSMCPProxyClientFactory
from mcp_proxy_for_aws.utils import (
    create_transport_with_sigv4,
    determine_aws_region,
    determine_service_name,
)


logger = logging.getLogger(__name__)


async def run_proxy(args) -> None:
    """Set up the server in MCP mode."""
    logger.info('Setting up mcp proxy server to %s', args.endpoint)

    # Validate and determine service
    service = determine_service_name(args.endpoint, args.service)
    logger.debug('Using service: %s', service)

    # Validate and determine region
    region = determine_aws_region(args.endpoint, args.region)
    logger.debug('Using region: %s', region)

    # Build metadata dictionary - start with AWS_REGION, then merge user metadata
    metadata = {'AWS_REGION': region}
    if args.metadata:
        metadata.update(args.metadata)

    # Get profile
    profile = args.profile

    # Log server configuration
    logger.info(
        'Using service: %s, region: %s, metadata: %s, profile: %s',
        service,
        region,
        metadata,
        profile,
    )

    timeout = httpx.Timeout(
        args.timeout,
        connect=args.connect_timeout,
        read=args.read_timeout,
        write=args.write_timeout,
    )

    # Create transport with SigV4 authentication
    transport = create_transport_with_sigv4(
        args.endpoint, service, region, metadata, timeout, profile
    )
    client_factory = AWSMCPProxyClientFactory(transport)

    try:
        proxy = AWSMCPProxy(
            client_factory=client_factory,
            name='MCP Proxy for AWS',
            instructions=(
                'MCP Proxy for AWS provides access to SigV4 protected MCP servers through a single interface. '
                'This proxy handles authentication and request routing to the appropriate backend services.'
            ),
        )
        proxy.add_middleware(InitializeMiddleware(client_factory))
        add_logging_middleware(proxy, args.log_level)
        add_tool_filtering_middleware(proxy, args.read_only)

        if args.retries:
            add_retry_middleware(proxy, args.retries)
        await proxy.run_async(transport='stdio', show_banner=False, log_level=args.log_level)
    except Exception as e:
        logger.error('Cannot start proxy server: %s', e)
        raise e
    finally:
        await client_factory.disconnect()


def add_tool_filtering_middleware(mcp: FastMCP, read_only: bool = False) -> None:
    """Add tool filtering middleware to target MCP server.

    Args:
        mcp: The FastMCP instance to add tool filtering to
        read_only: Whether or not to filter out tools that require write permissions
    """
    logger.info('Adding tool filtering middleware')
    mcp.add_middleware(
        ToolFilteringMiddleware(
            read_only=read_only,
        )
    )


def add_retry_middleware(mcp: FastMCP, retries: int) -> None:
    """Add retry with exponential backoff middleware to target MCP server.

    Args:
        mcp: The FastMCP instance to add exponential backoff to
        retries: number of retries with which to configure the retry middleware
    """
    logger.info('Adding retry middleware')
    mcp.add_middleware(RetryMiddleware(retries))


def add_logging_middleware(mcp: FastMCP, log_level: str) -> None:
    """Add logging middleware."""
    if log_level != 'DEBUG':
        return
    middleware_logger = logging.getLogger('mcp-proxy-for-aws-middleware-logger')
    middleware_logger.setLevel(log_level)
    mcp.add_middleware(
        LoggingMiddleware(
            logger=middleware_logger,
            log_level=middleware_logger.level,
            include_payloads=True,
            include_payload_length=True,
        )
    )


def main():
    """Run the MCP server."""
    args = parse_args()

    # Configure logging
    configure_logging(args.log_level)
    logger.info('Starting MCP Proxy for AWS Server')

    # Run the server
    try:
        asyncio.run(run_proxy(args))
    except Exception:
        logger.exception('Error launching MCP proxy for aws')
        return 1


if __name__ == '__main__':
    main()
