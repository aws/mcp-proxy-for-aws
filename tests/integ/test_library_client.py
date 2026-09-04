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

"""Integration tests for programmatic access against a remote MCP server.

The other integration tests drive the proxy path through `StdioTransport`. These cover the
library path, `aws_iam_streamablehttp_client`, which agent frameworks embed directly and which
therefore has no proxy middleware in front of it.
"""

import asyncio
import logging
import os
import pytest
from botocore.credentials import Credentials
from mcp import ClientSession, McpError
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client
from mcp_proxy_for_aws.utils import get_service_name_and_region_from_endpoint
from tests.integ.conftest import RemoteMCPServerConfiguration


logger = logging.getLogger(__name__)

_BUDGET_SECONDS = 60


def open_session(configuration: RemoteMCPServerConfiguration, **overrides):
    """Open a library-path session against the configured remote MCP server."""
    endpoint = configuration['endpoint']
    service, _ = get_service_name_and_region_from_endpoint(endpoint)

    return aws_iam_streamablehttp_client(
        endpoint=endpoint,
        aws_service=service,
        aws_region=configuration['region_name'],
        **overrides,
    )


@pytest.mark.asyncio(loop_scope='module')
async def test_library_client_completes_an_exchange(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration,
):
    """The library path can reach a real endpoint and list its tools."""

    async def exchange():
        async with open_session(remote_mcp_server_configuration) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                return await session.list_tools()

    result = await asyncio.wait_for(exchange(), timeout=_BUDGET_SECONDS)

    assert len(result.tools) > 0, f'Remote MCP server should have tools, got {result}'


@pytest.mark.skipif(
    not os.environ.get('AGENTCORE_RUNTIME_ARN'),
    reason='needs an endpoint that verifies SigV4; a local server accepts any signature',
)
@pytest.mark.asyncio(loop_scope='module')
async def test_library_client_reports_http_failure_to_the_caller(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration,
):
    """A real non-2xx reaches the caller as an error instead of leaving the request pending.

    Invalid credentials are used because a rejected signature is the one non-2xx a live
    endpoint returns deterministically; `tests/unit/test_mcp1_compat.py` covers the reported
    413 shape, which carries no body and no content type. Without the mcp 1.x workaround the
    failure raises out of the transport's own task group rather than answering this request,
    and a caller holding the session on a background event loop waits forever.
    """
    unusable = Credentials(access_key='AKIAIOSFODNN7EXAMPLE', secret_key='x' * 40)

    async def exchange():
        async with open_session(remote_mcp_server_configuration, credentials=unusable) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                with pytest.raises(McpError) as rejected:
                    await session.initialize()
                return str(rejected.value)

    message = await asyncio.wait_for(exchange(), timeout=_BUDGET_SECONDS)

    logger.info('Endpoint rejected the request with: %s', message)
    assert 'HTTP 4' in message, (
        f'Error should name the HTTP status the endpoint returned, got: {message}'
    )
