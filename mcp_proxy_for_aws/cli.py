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

"""Command-line interface argument parsing for MCP Proxy for AWS."""

import argparse
import os
from mcp_proxy_for_aws import __version__
from mcp_proxy_for_aws.utils import within_range
from typing import Any, Dict, Optional, Sequence


class KeyValueAction(argparse.Action):
    """Custom argparse action to parse key=value pairs into a dictionary."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: Optional[str] = None,
    ) -> None:
        """Parse key=value pairs into a dictionary.

        Args:
            parser: The argument parser
            namespace: The namespace object to update
            values: The values to parse (list of key=value strings)
            option_string: The option string that triggered this action
        """
        metadata: Dict[str, str] = {}
        # Ensure values is a sequence
        if values is None:
            # No values provided, set empty dict
            setattr(namespace, self.dest, metadata)
            return

        if isinstance(values, str):
            values = [values]

        for item in values:
            if '=' not in item:
                parser.error(f'Metadata must be in key=value format, got: {item}')
            key, value = item.split('=', 1)
            metadata[key] = value
        setattr(namespace, self.dest, metadata)


def parse_args():
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description=f'MCP Proxy for AWS v{__version__}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with your endpoint
  mcp-proxy-for-aws <SigV4 MCP endpoint URL>

  # Run with custom service and profile
  mcp-proxy-for-aws <SigV4 MCP endpoint URL> --service <aws-service> --profile default

  # Run with write permissions enabled
  mcp-proxy-for-aws <SigV4 MCP endpoint URL> --read-only
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
        help='AWS region to sign (uses AWS_REGION environment variable if not provided, with final fallback to us-east-1)',
        default=None,
    )

    parser.add_argument(
        '--metadata',
        nargs='*',
        action=KeyValueAction,
        default=None,
        help='Metadata to inject into MCP requests as key=value pairs (e.g., --metadata AWS_REGION=us-west-2 KEY=VALUE)',
    )

    parser.add_argument(
        '--read-only',
        action='store_true',
        help='Disable tools which may require write permissions (readOnlyHint True or unknown)',
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='ERROR',
        help='Set the logging level (default: ERROR)',
    )

    parser.add_argument(
        '--retries',
        type=int,
        default=0,
        choices=range(0, 11),
        metavar='[0-10]',
        help='Number of retries when calling endpoint mcp (default: 0) - setting this to 0 disables retries.',
    )

    parser.add_argument(
        '--timeout',
        type=within_range(0),
        default=180.0,
        help='Timeout (seconds) when connecting to endpoint (default: 180)',
    )

    parser.add_argument(
        '--connect-timeout',
        type=within_range(0),
        default=60.0,
        help='Connection timeout (seconds) when connecting to endpoint (default: 60)',
    )

    parser.add_argument(
        '--read-timeout',
        type=within_range(0),
        default=120.0,
        help='Read timeout (seconds) when connecting to endpoint (default: 120)',
    )

    parser.add_argument(
        '--write-timeout',
        type=within_range(0),
        default=180.0,
        help='Write timeout (seconds) when connecting to endpoint (default: 180)',
    )

    return parser.parse_args()
