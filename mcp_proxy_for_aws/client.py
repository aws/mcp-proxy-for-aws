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

import boto3
import logging
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from botocore.credentials import Credentials
from contextlib import _AsyncGeneratorContextManager
from datetime import timedelta
from mcp.client.streamable_http import GetSessionIdCallback, streamablehttp_client
from mcp.shared._httpx_utils import McpHttpClientFactory, create_mcp_http_client
from mcp.shared.message import SessionMessage
from mcp_proxy_for_aws.sigv4_helper import SigV4HTTPXAuth
from typing import Optional


logger = logging.getLogger(__name__)


def aws_iam_streamablehttp_client(
    endpoint: str,
    aws_service: str,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    credentials: Optional[Credentials] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float | timedelta = 30,
    sse_read_timeout: float | timedelta = 60 * 5,
    terminate_on_close: bool = True,
    httpx_client_factory: McpHttpClientFactory = create_mcp_http_client,
) -> _AsyncGeneratorContextManager[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
        GetSessionIdCallback,
    ],
    None,
]:
    """Create an AWS IAM-authenticated MCP streamable HTTP client.

    This function creates a context manager for connecting to an MCP server using AWS IAM
    authentication via SigV4 signing. Use with 'async with' to manage the connection lifecycle.

    Args:
        endpoint: The URL of the MCP server to connect to. Must be a valid HTTP/HTTPS URL.
        aws_service: The name of the AWS service the MCP server is hosted on, e.g. "bedrock-agentcore".
        aws_region: The AWS region name of the MCP server, e.g. "us-west-2".
        aws_profile: The AWS profile to use for authentication.
        credentials: Optional AWS credentials from boto3/botocore. If provided, takes precedence over aws_profile.
        headers: Optional additional HTTP headers to include in requests.
        timeout: Request timeout in seconds or timedelta object. Defaults to 30 seconds.
        sse_read_timeout: Server-sent events read timeout in seconds or timedelta object.
        terminate_on_close: Whether to terminate the connection on close.
        httpx_client_factory: Factory function for creating HTTPX clients.

    Returns:
        An async generator context manager that yields a tuple of transport components:
            - read_stream: MemoryObjectReceiveStream for reading server responses
            - write_stream: MemoryObjectSendStream for sending requests to server
            - get_session_id: Callback function to retrieve the current session ID

    Example:
        async with aws_iam_mcp_client(
            endpoint="https://example.com/mcp",
            aws_service="bedrock-agentcore",
            aws_region="us-west-2"
        ) as (read_stream, write_stream, get_session_id):
            # Use the streams here
            pass
    """
    logger.debug('Preparing AWS IAM MCP client for endpoint: %s', endpoint)

    if credentials is not None:
        creds = credentials
        region = aws_region
        if not region:
            raise ValueError(
                'AWS region must be specified via aws_region parameter when using credentials.'
            )
        logger.debug('Using provided AWS credentials')
    else:
        kwargs = {}
        if aws_profile is not None:
            kwargs['profile_name'] = aws_profile
        if aws_region is not None:
            kwargs['region_name'] = aws_region

        session = boto3.Session(**kwargs)
        creds = session.get_credentials()
        region = session.region_name

        if not region:
            raise ValueError(
                'AWS region must be specified via aws_region parameter,  AWS_REGION environment variable, or AWS config.'
            )

        logger.debug('AWS profile: %s', session.profile_name)

    logger.debug('AWS region: %s', region)
    logger.debug('AWS service: %s', aws_service)

    # Create a SigV4 authentication handler with AWS credentials
    auth = SigV4HTTPXAuth(creds, aws_service, region)

    # Return the streamable HTTP client context manager with AWS IAM authentication
    return streamablehttp_client(
        url=endpoint,
        headers=headers,
        timeout=timeout,
        sse_read_timeout=sse_read_timeout,
        terminate_on_close=terminate_on_close,
        httpx_client_factory=httpx_client_factory,
        auth=auth,
    )
