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
import httpx
import logging
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from botocore.credentials import Credentials
from collections.abc import AsyncGenerator
from datetime import timedelta
from mcp.client.streamable_http import GetSessionIdCallback, streamable_http_client
from mcp.shared._httpx_utils import McpHttpClientFactory, create_mcp_http_client
from mcp.shared.message import SessionMessage
from mcp_proxy_for_aws.sigv4_helper import SigV4HTTPXAuth
from typing_extensions import deprecated
from contextlib import asynccontextmanager


logger = logging.getLogger(__name__)


@asynccontextmanager
async def aws_iam_streamable_http_client(
    endpoint: str,
    aws_service: str,
    aws_region: str | None = None,
    aws_profile: str | None = None,
    credentials: Credentials | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
    terminate_on_close: bool = True,
) -> AsyncGenerator[
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
        http_client: Optional pre-configured httpx.AsyncClient. If not provided, one will be created with SigV4 auth.
        terminate_on_close: Whether to terminate the connection on close.

    Returns:
        An async generator yielding a tuple containing:
            - read_stream: MemoryObjectReceiveStream for reading server responses
            - write_stream: MemoryObjectSendStream for sending requests to server
            - get_session_id: Callback function to retrieve the current session ID

    Example:
        async with aws_iam_streamable_http_client(
            endpoint="https://example.com/mcp",
            aws_service="bedrock-agentcore",
            aws_region="us-west-2"
        ) as (read_stream, write_stream, get_session_id):
            # Use the streams here
            pass
    """
    logger.debug('Preparing AWS IAM MCP client for endpoint: %s', endpoint)

    # If http_client is provided, use it directly
    if http_client is not None:
        logger.debug('Using provided http_client')
        async with streamable_http_client(
            url=endpoint,
            http_client=http_client,
            terminate_on_close=terminate_on_close,
        ) as streams:
            yield streams
        return

    # Otherwise, create http_client with AWS IAM authentication
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

    # Create HTTP client with AWS IAM authentication
    client = httpx.AsyncClient(
        auth=auth,
        headers={'Accept': 'application/json, text/event-stream'},
    )

    # Return the streamable HTTP client context manager with AWS IAM authentication
    async with streamable_http_client(
        url=endpoint,
        http_client=client,
        terminate_on_close=terminate_on_close,
    ) as streams:
        yield streams


@asynccontextmanager
@deprecated("Use `aws_iam_streamable_http_client` instead.")
async def aws_iam_streamablehttp_client(
    endpoint: str,
    aws_service: str,
    aws_region: str | None = None,
    aws_profile: str | None = None,
    credentials: Credentials | None = None,
    headers: dict[str, str] | None = None,
    timeout: float | timedelta = 30,
    sse_read_timeout: float | timedelta = 60 * 5,
    terminate_on_close: bool = True,
    httpx_client_factory: McpHttpClientFactory = create_mcp_http_client,
) -> AsyncGenerator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
        GetSessionIdCallback,
    ],
    None,
]:
    """Create an AWS IAM-authenticated MCP streamable HTTP client.

    This is a deprecated alias for aws_iam_streamable_http_client.
    Please update your code to use aws_iam_streamable_http_client instead.

    This function maintains backward compatibility by accepting the legacy parameters
    and creating a properly configured httpx.AsyncClient to pass to the new implementation.
    """
    # Resolve credentials and region
    if credentials is not None:
        creds = credentials
        region = aws_region
        if not region:
            raise ValueError(
                'AWS region must be specified via aws_region parameter when using credentials.'
            )
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

    # Create SigV4 authentication
    auth = SigV4HTTPXAuth(creds, aws_service, region)

    # Convert timeout to httpx.Timeout
    if isinstance(timeout, timedelta):
        timeout_seconds = timeout.total_seconds()
    else:
        timeout_seconds = timeout

    if isinstance(sse_read_timeout, timedelta):
        sse_timeout_seconds = sse_read_timeout.total_seconds()
    else:
        sse_timeout_seconds = sse_read_timeout

    httpx_timeout = httpx.Timeout(timeout_seconds, read=sse_timeout_seconds)

    # Create httpx client using the factory with legacy parameters
    http_client = httpx_client_factory(
        headers=headers,
        timeout=httpx_timeout,
        auth=auth,
    )

    # Delegate to the new function with the configured client
    async with aws_iam_streamable_http_client(
        endpoint=endpoint,
        aws_service=aws_service,
        aws_region=region,
        aws_profile=aws_profile,
        credentials=creds,
        http_client=http_client,
        terminate_on_close=terminate_on_close,
    ) as streams:
        # Yield the streams tuple - @asynccontextmanager handles the rest
        yield streams
