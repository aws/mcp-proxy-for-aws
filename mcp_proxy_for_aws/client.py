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

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Optional

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.client.streamable_http import (
    GetSessionIdCallback,
    create_mcp_http_client,
    streamablehttp_client
)
from mcp.shared._httpx_utils import McpHttpClientFactory
from mcp.shared.message import SessionMessage

from mcp_proxy_for_aws.sigv4_helper import SigV4HTTPXAuth


logger = logging.getLogger(__name__)

@asynccontextmanager
async def aws_iam_mcp_client(
    endpoint: str,
    aws_service: str,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: Optional[float | timedelta] = 30,
    sse_read_timeout: Optional[float | timedelta] = 300,
    terminate_on_close: Optional[bool] = True,
    httpx_client_factory: Optional[McpHttpClientFactory] = create_mcp_http_client,
) -> AsyncGenerator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
        GetSessionIdCallback,
    ],
    None,
]:
    """
    Create an AWS IAM-authenticated MCP streamable HTTP client.

    This function establishes a connection to an MCP server using AWS IAM authentication
    via SigV4 signing. It returns the raw transport components for use with MCP client
    sessions or framework integrations.

    Args:
        endpoint: The URL of the MCP server to connect to. Must be a valid HTTP/HTTPS URL.
        aws_service: The name of the AWS service the MCP server is hosted on, e.g. "bedrock-agentcore".
        aws_region: The AWS region name of the MCP server, e.g. "us-west-2".
        aws_profile: The AWS profile to use for authentication.
        headers: Optional additional HTTP headers to include in requests.
        timeout: Request timeout in seconds or timedelta object. Defaults to 30 seconds.
        sse_read_timeout: Server-sent events read timeout in seconds or timedelta object.
        terminate_on_close: Whether to terminate the connection on close.
        httpx_client_factory: Factory function for creating HTTPX clients.

    Yields:
        tuple: Transport components for MCP communication:
            - read_stream: Async generator for reading server responses
            - write_stream: Async generator for sending requests to server
            - get_session_id: Function to retrieve the current session ID
    """
    # Create a SigV4 authentication handler with AWS credentials
    logger.info("Preparing AWS IAM MCP client for endpoint: %s", endpoint)
    
    kwargs = {}
    if aws_region is not None:
        kwargs['region_name'] = aws_region
    if aws_profile is not None:
        kwargs['profile_name'] = aws_profile

    # Create a boto3 session with the provided arguments
    session = boto3.Session(**kwargs)

    profile = session.profile_name
    region = session.region_name
    
    logger.debug("AWS profile: %s", profile)
    logger.debug("AWS region: %s", region)
    logger.debug("AWS service: %s", aws_service)
    
    # Create a SigV4 authentication handler with AWS credentials
    auth = SigV4HTTPXAuth(session.get_credentials(), aws_service, region)
    
    # Establish connection using MCP SDK's streamable HTTP client
    async with streamablehttp_client(
        url=endpoint,
        auth=auth,
        headers=headers,
        timeout=timeout,
        sse_read_timeout=sse_read_timeout,
        terminate_on_close=terminate_on_close,
        httpx_client_factory=httpx_client_factory,
    ) as (read_stream, write_stream, get_session_id):
        # Return transport components for external session management
        logger.info("Successfully prepared AWS IAM MCP client for endpoint: %s", endpoint)
        yield (read_stream, write_stream, get_session_id)
