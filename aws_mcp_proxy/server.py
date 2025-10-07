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

"""AWS MCP Proxy Server entry point.

This server provides a unified interface to backend servers by:
1. Using JSON-RPC calls to MCP endpoints for a single backend server
2. Loading tools from configured backend servers
3. Registering tools with prefixed names
4. Providing tool listing functionality through the MCP protocol
5. Supporting tool refresh
"""

import argparse
import asyncio
import logging
import os
from aws_mcp_proxy.logging_config import configure_logging
from aws_mcp_proxy.middleware.tool_filter import ToolFilteringMiddleware
from aws_mcp_proxy.utils import (
    create_transport_with_sigv4,
    determine_aws_region,
    determine_service_name,
)
from fastmcp.server.middleware.error_handling import RetryMiddleware
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.server.server import FastMCP
from typing import Any


logger = logging.getLogger(__name__)


async def setup_mcp_mode(local_mcp: FastMCP, args) -> None:
    """Set up the server in MCP mode."""
    logger.info('Setting up server in MCP mode')

    # Validate and determine service
    service = determine_service_name(args.endpoint, args.service)
    logger.debug('Using service: %s', service)

    # Validate and determine region
    region = determine_aws_region(args.endpoint, args.region)
    logger.debug('Using region: %s', region)

    # Get profile
    profile = args.profile

    # Log server configuration
    logger.info('Using service: %s, region: %s, profile: %s', service, region, profile)
    logger.info('Running in MCP mode')

    # Create transport with SigV4 authentication
    transport = create_transport_with_sigv4(args.endpoint, service, region, profile)

    # Create proxy with the transport
    proxy = FastMCP.as_proxy(transport)
    add_logging_middleware(proxy, args.log_level)
    add_tool_filtering_middleware(proxy, args.read_only)

    if args.retries:
        add_retry_middleware(proxy, args.retries)

    await proxy.run_async()


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


def add_logging_middleware(mcp: FastMCP, log_level: int) -> None:
    """Add logging middleware."""
    middleware_logger = logging.getLogger('aws-mcp-proxy-middleware-logger')
    middleware_logger.setLevel(log_level)
    mcp.add_middleware(
        LoggingMiddleware(
            logger=middleware_logger,
            log_level=middleware_logger.level,
            include_payloads=True,
            include_payload_length=True,
        )
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='AWS MCP Proxy Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with your endpoint
  aws-mcp-proxy <SigV4 MCP endpoint URL>

  # Run with custom service and profile
  aws-mcp-proxy <SigV4 MCP endpoint URL> --service <aws-service> --profile default

  # Run with write permissions enabled
  aws-mcp-proxy <SigV4 MCP endpoint URL> --read-only
        """,
    )

    parser.add_argument(
        'endpoint',
        help='SigV4 MCP endpoint URL',
    )

    parser.add_argument(
        '--service',
        help='AWS service name for SigV4 signing (inferred from endpoint if not provided)',
    )

    parser.add_argument(
        '--profile',
        help='AWS profile to use (uses AWS_PROFILE environment variable if not provided)',
        default=os.getenv('AWS_PROFILE'),
    )

    parser.add_argument(
        '--region',
        help='AWS region to use (uses AWS_REGION environment variable if not provided, with final fallback to us-east-1)',
        default=None,
    )

    parser.add_argument(
        '--read-only',
        action='store_true',
        help='Disable tools which may require write permissions (readOnlyHint True or unknown)',
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level (default: INFO)',
    )

    parser.add_argument(
        '--retries',
        type=int,
        default=0,
        choices=range(0, 11),
        metavar='[0-10]',
        help='Number of retries when calling endpoint mcp (default: 0) - setting this to 0 disables retries.',
    )

    return parser.parse_args()


def main():
    """Run the MCP server."""
    args = parse_args()

    # Configure logging
    configure_logging(args.log_level)
    logger.info('Starting AWS MCP Proxy Server')

    # Create FastMCP instance
    mcp = FastMCP[Any](
        name='MCP Proxy',
        instructions=(
            'AWS MCP Proxy Server that provides access to backend servers through a single interface. '
            'This proxy handles authentication and request routing to the appropriate backend services.'
        ),
    )

    async def setup_and_run():
        try:
            await setup_mcp_mode(mcp, args)

            logger.info('Server setup complete, starting MCP server')

        except Exception as e:
            logger.error('Failed to start server: %s', e)
            raise

    # Run the server
    asyncio.run(setup_and_run())


if __name__ == '__main__':
    main()
