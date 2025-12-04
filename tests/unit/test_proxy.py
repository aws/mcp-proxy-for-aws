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
from fastmcp.exceptions import NotFoundError
from fastmcp.tools import Tool
from mcp import McpError
from mcp.types import ErrorData, InitializeRequest, JSONRPCError
from mcp_proxy_for_aws.proxy import (
    AWSMCPProxy,
    AWSMCPProxyClient,
    AWSMCPProxyClientFactory,
    AWSProxyToolManager,
)
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
async def test_tool_manager_get_tool_with_cache():
    """Test get_tool returns from cache when available."""
    mock_factory = Mock()
    manager = AWSProxyToolManager(mock_factory)
    mock_tool = Mock(spec=Tool)
    manager._cached_tools = {'test_tool': mock_tool}

    result = await manager.get_tool('test_tool')
    assert result == mock_tool


@pytest.mark.asyncio
async def test_tool_manager_get_tool_without_cache():
    """Test get_tool fetches tools when cache is empty."""
    mock_factory = Mock()
    manager = AWSProxyToolManager(mock_factory)
    mock_tool = Mock(spec=Tool)

    with patch.object(manager, 'get_tools', return_value={'test_tool': mock_tool}):
        result = await manager.get_tool('test_tool')
        assert result == mock_tool
        assert manager._cached_tools == {'test_tool': mock_tool}


@pytest.mark.asyncio
async def test_tool_manager_get_tool_not_found():
    """Test get_tool raises NotFoundError when tool doesn't exist."""
    mock_factory = Mock()
    manager = AWSProxyToolManager(mock_factory)
    manager._cached_tools = {}

    with pytest.raises(NotFoundError, match="Tool 'missing_tool' not found"):
        await manager.get_tool('missing_tool')


@pytest.mark.asyncio
async def test_tool_manager_get_tools_updates_cache():
    """Test get_tools updates the cache."""
    mock_factory = Mock()
    manager = AWSProxyToolManager(mock_factory)
    mock_tools = {'tool1': Mock(spec=Tool), 'tool2': Mock(spec=Tool)}

    with patch('mcp_proxy_for_aws.proxy._ProxyToolManager.get_tools', return_value=mock_tools):
        result = await manager.get_tools()
        assert result == mock_tools
        assert manager._cached_tools == mock_tools


def test_proxy_initialization():
    """Test AWSMCPProxy initializes with custom tool manager."""
    mock_factory = Mock()
    proxy = AWSMCPProxy(client_factory=mock_factory, name='test')
    assert isinstance(proxy._tool_manager, AWSProxyToolManager)


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
