#!/usr/bin/env python3
"""Manual CLI test tool for AWS MCP Proxy.

This tool allows manual testing of MCP client functionality against remote MCP servers.
"""

import argparse
import asyncio
import logging
import os
import sys
from typing import Optional


# Add the parent directory to sys.path to import the mcp module
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests.integ.mcp.simple_mcp_client import build_mcp_client


logger = logging.getLogger(__name__)


def setup_logging(log_level: str = 'INFO') -> None:
    """Set up logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()],
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Manual CLI test tool for AWS MCP Proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (service inferred from endpoint)
  uv run tests/integ/manual_test.py --endpoint https://my-mcp-server.amazonaws.com --list-tools

  # With explicit service and region
  uv run tests/integ/manual_test.py --endpoint https://my-endpoint.com --service bedrock --region us-west-2 --list-tools

  # Service override example
  uv run tests/integ/manual_test.py --endpoint https://custom-endpoint.com --service lambda --list-tools
        """,
    )

    parser.add_argument(
        '--endpoint',
        required=True,
        help='MCP server endpoint URL',
    )

    parser.add_argument(
        '--service',
        help='AWS service name for SigV4 signing (inferred from endpoint if not provided)',
    )

    parser.add_argument(
        '--region',
        help='AWS region to use (uses AWS_REGION environment variable if not provided, with final fallback to us-east-1)',
        default=os.getenv('AWS_REGION', 'us-east-1'),
    )

    parser.add_argument(
        '--list-tools',
        action='store_true',
        help='List available tools from the MCP server',
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level (default: INFO)',
    )

    return parser.parse_args()


async def list_tools_command(endpoint: str, region: str, service: Optional[str] = None) -> None:
    """Execute the list-tools command."""
    logger.info(f'Connecting to MCP server at: {endpoint}')
    logger.info(f'Using region: {region}')
    if service:
        logger.info(f'Using service: {service}')
    else:
        logger.info('Service will be inferred from endpoint')

    try:
        # Build MCP client
        client = build_mcp_client(endpoint=endpoint, region_name=region, service=service)

        # Connect and list tools
        async with client:
            logger.info('Connected to MCP server, listing tools...')
            tools = await client.list_tools()

            if not tools:
                print('\nNo tools found on the MCP server.')
                return

            print(f'\nFound {len(tools)} tool(s) on the MCP server:')
            print('=' * 50)

            for i, tool in enumerate(tools, 1):
                print(f'{i}. {tool.name}')
                if hasattr(tool, 'description') and tool.description:
                    print(f'   Description: {tool.description}')
                if hasattr(tool, 'inputSchema') and tool.inputSchema:
                    print(f'   Input Schema: {tool.inputSchema}')
                print()

    except KeyboardInterrupt:
        logger.info('Operation cancelled by user')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Error connecting to MCP server: {e}')
        sys.exit(1)


async def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Set up logging
    setup_logging(args.log_level)

    # Validate arguments
    if not args.list_tools:
        logger.error('No action specified. Use --list-tools to list available tools.')
        sys.exit(1)

    # Execute the requested command
    if args.list_tools:
        await list_tools_command(endpoint=args.endpoint, region=args.region, service=args.service)


if __name__ == '__main__':
    asyncio.run(main())
