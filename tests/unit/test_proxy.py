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

"""Tests for proxy module."""

import httpx
import pytest
from fastmcp.client.transports import ClientTransport
from fastmcp.exceptions import ToolError
from fastmcp.tools.tool import ToolResult
from mcp import McpError
from mcp.types import ErrorData, InitializeRequest, JSONRPCError
from mcp_proxy_for_aws.proxy import (
    AWSMCPProxy,
    AWSMCPProxyClient,
    AWSMCPProxyClientFactory,
    AWSProxyProvider,
    AWSProxyTool,
)
from mcp_proxy_for_aws.sigv4_helper import UpstreamAuthenticationError
from unittest.mock import AsyncMock, Mock, patch


# ---------------------------------------------------------------------------
# AWSProxyTool tests (replaces AWSProxyToolManager tests)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_tool_run_success():
    """Test AWSProxyTool.run passes through on success."""
    expected_result = ToolResult(content=[], structured_content=None)

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        return_value=expected_result,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        result = await tool.run({'arg': 'value'})
        assert result == expected_result


@pytest.mark.asyncio
async def test_proxy_tool_run_http_401_raises_tool_error():
    """Test AWSProxyTool.run converts HTTP 401 to ToolError."""
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.headers = {
        'www-authenticate': 'Bearer scope="aws.sigv4"'
    }
    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=http_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Authentication required'):
            await tool.run({})


@pytest.mark.asyncio
async def test_proxy_tool_run_mcp_error_401_raises_tool_error():
    """Test AWSProxyTool.run converts McpError with 401 data to ToolError."""
    mcp_error = McpError(
        error=ErrorData(
            code=-32001,
            message='Authentication required',
            data={'status_code': 401, 'www_authenticate': 'Bearer scope="aws.sigv4"'},
        )
    )

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=mcp_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Authentication required'):
            await tool.run({})


@pytest.mark.asyncio
async def test_proxy_tool_run_non_401_http_error_reraises():
    """Test AWSProxyTool.run re-raises non-401 HTTPStatusError."""
    mock_response = Mock()
    mock_response.status_code = 500
    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=http_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(httpx.HTTPStatusError):
            await tool.run({})


@pytest.mark.asyncio
async def test_proxy_tool_run_non_401_mcp_error_reraises():
    """Test AWSProxyTool.run re-raises non-401 McpError."""
    mcp_error = McpError(
        error=ErrorData(
            code=-32600,
            message='Invalid Request',
        )
    )

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=mcp_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(McpError) as exc_info:
            await tool.run({})
        assert exc_info.value.error.code == -32600


@pytest.mark.asyncio
async def test_proxy_tool_run_upstream_auth_error():
    """Test AWSProxyTool.run catches UpstreamAuthenticationError and converts to ToolError."""
    auth_error = UpstreamAuthenticationError(
        401, 'Bearer scope="aws.sigv4"', 'Unauthorized'
    )

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=auth_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Authentication required') as exc_info:
            await tool.run({})
        assert 'Bearer scope="aws.sigv4"' in str(exc_info.value)


@pytest.mark.asyncio
async def test_proxy_tool_run_wrapped_upstream_auth_error():
    """Test AWSProxyTool.run unwraps UpstreamAuthenticationError from exception chain."""
    auth_error = UpstreamAuthenticationError(
        401, 'Bearer scope="aws.sigv4"', 'Unauthorized'
    )
    # Simulate anyio/MCP wrapping the auth error in a RuntimeError
    wrapper_error = RuntimeError('Task group failed')
    wrapper_error.__cause__ = auth_error

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=wrapper_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Authentication required') as exc_info:
            await tool.run({})
        assert 'Bearer scope="aws.sigv4"' in str(exc_info.value)


@pytest.mark.asyncio
async def test_proxy_tool_run_deeply_wrapped_upstream_auth_error():
    """Test AWSProxyTool.run unwraps UpstreamAuthenticationError from deep exception chain."""
    auth_error = UpstreamAuthenticationError(401, 'Bearer', 'Unauthorized')
    # Double-wrapped: RuntimeError -> Exception -> UpstreamAuthenticationError
    inner_wrapper = Exception('inner')
    inner_wrapper.__cause__ = auth_error
    outer_wrapper = RuntimeError('outer')
    outer_wrapper.__cause__ = inner_wrapper

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=outer_wrapper,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Authentication required'):
            await tool.run({})


@pytest.mark.asyncio
async def test_proxy_tool_run_generic_exception_reraises():
    """Test AWSProxyTool.run re-raises generic exceptions that don't wrap auth errors."""
    generic_error = RuntimeError('Something unrelated')

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=generic_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(RuntimeError, match='Something unrelated'):
            await tool.run({})


@pytest.mark.asyncio
async def test_proxy_tool_run_tool_error_passthrough():
    """Test AWSProxyTool.run re-raises ToolError without wrapping."""
    tool_error = ToolError('Some tool error')

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyTool.run',
        side_effect=tool_error,
    ):
        tool = AWSProxyTool(
            client_factory=Mock(),
            name='test_tool',
            description='test',
            parameters={'type': 'object', 'properties': {}},
        )
        with pytest.raises(ToolError, match='Some tool error'):
            await tool.run({})


# ---------------------------------------------------------------------------
# AWSProxyProvider tests
# ---------------------------------------------------------------------------


def test_proxy_provider_cache_starts_empty():
    """Test AWSProxyProvider cache starts as None."""
    provider = AWSProxyProvider(client_factory=Mock())
    assert provider._cached_tools is None


def test_proxy_provider_invalidate_cache():
    """Test AWSProxyProvider.invalidate_cache resets cache."""
    provider = AWSProxyProvider(client_factory=Mock())
    provider._cached_tools = [Mock()]
    provider.invalidate_cache()
    assert provider._cached_tools is None


# ---------------------------------------------------------------------------
# AWSMCPProxy tests
# ---------------------------------------------------------------------------


def test_proxy_initialization():
    """Test AWSMCPProxy initializes with AWSProxyProvider."""
    mock_factory = Mock()
    proxy = AWSMCPProxy(client_factory=mock_factory, name='test')
    # The proxy should have an AWSProxyProvider
    providers = [p for p in proxy.providers if isinstance(p, AWSProxyProvider)]
    assert len(providers) == 1


# ---------------------------------------------------------------------------
# AWSMCPProxyClient tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_client_connect_success():
    """Test successful connection."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', return_value='connected'):
        result = await client._connect()
        assert result == 'connected'


@pytest.mark.asyncio
async def test_proxy_client_connect_http_error_with_mcp_error():
    """Test connection failure with MCP error response."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    error_data = ErrorData(code=-32600, message='Invalid Request')
    jsonrpc_error = JSONRPCError(jsonrpc='2.0', id=1, error=error_data)

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=jsonrpc_error.model_dump_json().encode())

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=http_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32600
        assert exc_info.value.error.message == 'Invalid Request'


@pytest.mark.asyncio
async def test_proxy_client_connect_http_error_non_mcp():
    """Test connection failure with non-MCP HTTP error."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=b'Not a JSON-RPC message')

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=http_error):
        with pytest.raises(httpx.HTTPStatusError):
            await client._connect()


@pytest.mark.asyncio
async def test_proxy_client_aexit_does_not_disconnect():
    """Test __aexit__ does not disconnect the client."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    result = await client.__aexit__(None, None, None)
    assert result is None


def test_client_factory_initialization():
    """Test factory initialization."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    assert factory._transport == mock_transport
    assert factory._client is None
    assert factory._initialize_request is None


def test_client_factory_set_init_params():
    """Test setting initialization parameters."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    mock_request = Mock(spec=InitializeRequest)
    factory.set_init_params(mock_request)

    assert factory._initialize_request == mock_request


@pytest.mark.asyncio
async def test_client_factory_get_client_when_connected():
    """Test get_client returns existing client when connected."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    mock_client = Mock(spec=AWSMCPProxyClient)
    factory._client = mock_client

    client = await factory.get_client()
    assert client == mock_client


@pytest.mark.asyncio
async def test_client_factory_get_client_when_disconnected():
    """Test get_client creates new client when disconnected."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    client = await factory.get_client()
    assert isinstance(client, AWSMCPProxyClient)
    assert factory._client == client


@pytest.mark.asyncio
async def test_client_factory_callable_interface():
    """Test factory callable interface."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    client = await factory()
    assert isinstance(client, AWSMCPProxyClient)


@pytest.mark.asyncio
async def test_client_factory_disconnect_all():
    """Test disconnect disconnects the client."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    mock_client = Mock()
    mock_client._disconnect = AsyncMock()
    factory._client = mock_client

    await factory.disconnect()

    mock_client._disconnect.assert_called_once_with(force=True)


@pytest.mark.asyncio
async def test_client_factory_disconnect_all_handles_exceptions():
    """Test disconnect handles exceptions gracefully."""
    mock_transport = Mock(spec=ClientTransport)
    factory = AWSMCPProxyClientFactory(mock_transport)

    mock_client = Mock()
    mock_client._disconnect = AsyncMock(side_effect=Exception('Disconnect failed'))
    factory._client = mock_client

    await factory.disconnect()

    mock_client._disconnect.assert_called_once_with(force=True)


@pytest.mark.asyncio
async def test_proxy_client_connect_runtime_error_with_mcp_error():
    """Test connection handles RuntimeError wrapping McpError."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    error_data = ErrorData(code=-32600, message='Invalid Request')
    mcp_error = McpError(error=error_data)
    runtime_error = RuntimeError('Connection failed')
    runtime_error.__cause__ = mcp_error

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=runtime_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32600


@pytest.mark.asyncio
async def test_proxy_client_connect_runtime_error_max_retries():
    """Test connection stops retrying after max_connect_retry."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport, max_connect_retry=2)

    runtime_error = RuntimeError('Connection failed')

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=runtime_error):
        with patch.object(client, '_disconnect', new_callable=AsyncMock) as mock_disconnect:
            with pytest.raises(RuntimeError):
                await client._connect()
            assert mock_disconnect.call_count == 3


@pytest.mark.asyncio
async def test_proxy_client_connect_runtime_error_with_timeout():
    """Test connection handles TimeoutException during disconnect."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport, max_connect_retry=1)

    runtime_error = RuntimeError('Connection failed')
    call_count = 0

    async def mock_connect_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise runtime_error
        return 'connected'

    with patch(
        'mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=mock_connect_side_effect
    ):
        with patch.object(
            client,
            '_disconnect',
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException('timeout'),
        ):
            result = await client._connect()
            assert result == 'connected'


@pytest.mark.asyncio
async def test_proxy_client_max_connect_retry_default():
    """Test default max_connect_retry is 3."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)
    assert client._max_connect_retry == 3


@pytest.mark.asyncio
async def test_proxy_client_connect_http_401_with_www_authenticate():
    """Test connection failure with HTTP 401 extracts WWW-Authenticate header."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.headers = {
        'www-authenticate': 'Bearer resource_metadata="/.well-known/oauth-protected-resource", scope="aws.sigv4"'
    }

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=http_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32001
        assert exc_info.value.error.message == 'Authentication required'
        assert exc_info.value.error.data['status_code'] == 401
        assert 'Bearer' in exc_info.value.error.data['www_authenticate']


@pytest.mark.asyncio
async def test_proxy_client_connect_http_401_without_www_authenticate():
    """Test connection failure with HTTP 401 when no WWW-Authenticate header."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.headers = {}

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=http_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32001
        assert exc_info.value.error.data['status_code'] == 401
        assert exc_info.value.error.data['www_authenticate'] == ''


@pytest.mark.asyncio
async def test_proxy_client_connect_upstream_auth_error():
    """Test _connect() catches UpstreamAuthenticationError and converts to McpError."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    auth_error = UpstreamAuthenticationError(
        401, 'Bearer scope="aws.sigv4"', 'Unauthorized'
    )

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=auth_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32001
        assert exc_info.value.error.message == 'Authentication required'
        assert exc_info.value.error.data['status_code'] == 401
        assert exc_info.value.error.data['www_authenticate'] == 'Bearer scope="aws.sigv4"'


@pytest.mark.asyncio
async def test_proxy_client_connect_upstream_auth_error_no_www_authenticate():
    """Test _connect() handles UpstreamAuthenticationError with empty WWW-Authenticate."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    auth_error = UpstreamAuthenticationError(401, '')

    with patch('mcp_proxy_for_aws.proxy._ProxyClient._connect', side_effect=auth_error):
        with pytest.raises(McpError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32001
        assert exc_info.value.error.data['www_authenticate'] == ''
