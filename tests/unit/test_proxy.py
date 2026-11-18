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

import asyncio
import httpx2
import pytest
from botocore.exceptions import LoginRefreshRequired, LoginTokenLoadError, NoRegionError
from fastmcp import FastMCP
from fastmcp.client.transports import ClientTransport, FastMCPTransport
from mcp import MCPError
from mcp.types import ErrorData, InitializeRequest, JSONRPCError
from mcp_proxy_for_aws.proxy import (
    AWSMCPProxyClient,
    AWSMCPProxyClientFactory,
)
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
async def test_proxy_client_connect_success():
    """Test successful connection."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', return_value='connected'):
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

    http_error = httpx2.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=http_error):
        with pytest.raises(MCPError) as exc_info:
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

    http_error = httpx2.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=http_error):
        with pytest.raises(httpx2.HTTPStatusError):
            await client._connect()


@pytest.mark.asyncio
async def test_proxy_client_stays_connected_across_context_exits():
    """Leaving a context must leave the backend connection up, without leaking nesting.

    stdio has no way to say "session over" short of closing the pipe, so the connection has
    to outlive each ``async with`` block -- but the nesting counter still has to unwind, or
    the base client's own teardown path can never fire. Driven through a real connection:
    asserting ``__aexit__``'s return value proves neither half.
    """
    backend = FastMCP('backend-server')

    @backend.tool()
    def backend_tool() -> str:
        """A backend tool."""
        return 'ok'

    client = AWSMCPProxyClient(FastMCPTransport(backend))
    try:
        for _ in range(3):
            async with client:
                assert client.is_connected()
            assert client.is_connected(), 'backend connection was dropped on context exit'

        assert client._session_state.nesting_counter == 0, (
            'context exits did not unwind the nesting counter'
        )
    finally:
        await client._disconnect(force=True)


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
    """Test connection handles RuntimeError wrapping MCPError."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    mcp_error = MCPError(code=-32600, message='Invalid Request')
    runtime_error = RuntimeError('Connection failed')
    runtime_error.__cause__ = mcp_error

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=runtime_error):
        with pytest.raises(MCPError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32600


@pytest.mark.asyncio
async def test_proxy_client_connect_runtime_error_max_retries():
    """Test connection stops retrying after max_connect_retry."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport, max_connect_retry=2)

    runtime_error = RuntimeError('Connection failed')

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=runtime_error):
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
        'mcp_proxy_for_aws.proxy.StatefulProxyClient._connect',
        side_effect=mock_connect_side_effect,
    ):
        with patch.object(
            client,
            '_disconnect',
            new_callable=AsyncMock,
            side_effect=httpx2.TimeoutException('timeout'),
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
async def test_proxy_client_connect_credential_error():
    """Test connection converts RuntimeError wrapping credential ValueError to MCPError."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    credential_error = ValueError(
        'No AWS credentials available. Configure credentials or use --skip-auth to send unsigned requests.'
    )
    runtime_error = RuntimeError('Client failed to connect')
    runtime_error.__cause__ = credential_error

    with patch('mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=runtime_error):
        with pytest.raises(MCPError) as exc_info:
            await client._connect()
        assert exc_info.value.error.code == -32603
        assert 'credentials' in exc_info.value.error.message.lower()
        assert '--skip-auth' in exc_info.value.error.message


class TestRejectedCredentialsThroughTheRealTransport:
    """Drive the real HTTP transport against a server that rejects the signature.

    Unit tests that raise a hand-built HTTPStatusError cannot show what the SDK does with a real
    403, which is to answer with a stand-in error and drop the status. This goes the whole way.
    """

    @pytest.fixture
    def rejecting_endpoint(self):
        """A local endpoint that answers every POST with a plain 403."""
        import http.server
        import json as _json
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get('content-length', 0)))
                body = _json.dumps(
                    {'message': 'The security token included in the request is invalid.'}
                ).encode()
                self.send_response(403)
                self.send_header('content-type', 'application/json')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f'http://127.0.0.1:{server.server_port}/mcp'
        server.shutdown()
        server.server_close()

    @pytest.mark.asyncio
    async def test_connect_surfaces_what_the_endpoint_said_and_the_status(
        self, rejecting_endpoint, monkeypatch
    ):
        """The caller gets an MCPError with the status and the endpoint's own words."""
        import httpx2
        from mcp import MCPError
        from mcp_proxy_for_aws.middleware.tool_error_middleware import ToolErrorMiddleware
        from mcp_proxy_for_aws.utils import create_transport_with_sigv4

        monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'test')
        monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'test')
        monkeypatch.setenv('AWS_SESSION_TOKEN', 'test')
        transport = create_transport_with_sigv4(
            rejecting_endpoint, 'aws-mcp', 'us-east-1', {}, httpx2.Timeout(5)
        )
        client = AWSMCPProxyClient(transport)

        with pytest.raises(BaseException) as raised:
            await client._connect()

        error = raised.value
        assert isinstance(error, MCPError)
        assert error.code == 403
        assert 'security token included in the request is invalid' in str(error)
        assert ToolErrorMiddleware._is_credential_error(error)


def _factory_with_client(connect):
    """A real factory around a mock client whose ``_connect`` runs ``connect``."""
    client = Mock()
    client._connect = AsyncMock(side_effect=connect)
    factory = AWSMCPProxyClientFactory(Mock())
    factory._client = client
    return factory, client


@pytest.mark.asyncio
async def test_ensure_connected_connects_once():
    """Repeated calls leave the connection as the first one opened it."""
    factory, client = _factory_with_client(AsyncMock())

    for _ in range(3):
        assert await factory.ensure_connected() is client

    client._connect.assert_awaited_once()
    assert factory.connected


@pytest.mark.asyncio
async def test_ensure_connected_connects_once_when_called_concurrently():
    """Callers racing to be first must not each open their own connection."""

    async def slow_connect():
        await asyncio.sleep(0.05)

    factory, client = _factory_with_client(slow_connect)

    await asyncio.gather(*(factory.ensure_connected() for _ in range(5)))

    client._connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_connected_retries_after_a_failed_connect():
    """A connect that failed leaves the factory unconnected, so the next call tries again."""
    attempts = []

    async def flaky_connect():
        attempts.append(1)
        if len(attempts) == 1:
            raise MCPError(code=-32603, message='down')

    factory, client = _factory_with_client(flaky_connect)

    with pytest.raises(MCPError, match='down'):
        await factory.ensure_connected()
    assert not factory.connected

    await factory.ensure_connected()
    assert factory.connected
    assert client._connect.await_count == 2


@pytest.mark.asyncio
async def test_ensure_connected_does_not_trust_a_half_open_session():
    """The client reports itself connected once its session object exists, before the handshake."""
    factory, client = _factory_with_client(AsyncMock())
    client.is_connected = Mock(return_value=True)

    await factory.ensure_connected()

    client._connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_disconnect_marks_the_factory_unconnected():
    """After a disconnect the next caller opens a fresh connection."""
    factory, client = _factory_with_client(AsyncMock())
    client._disconnect = AsyncMock()

    await factory.ensure_connected()
    await factory.disconnect()
    assert not factory.connected

    await factory.ensure_connected()
    assert client._connect.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('botocore_error', 'expected_hint'),
    [
        (LoginRefreshRequired(), "'aws login'"),
        (
            LoginTokenLoadError(
                error_msg='Unable to load a existing login session for session '
                'arn:aws:iam::123456789012:user/example. '
                "Please reauthenticate with 'aws login'."
            ),
            "'aws login'",
        ),
        (NoRegionError(), 'You must specify a region.'),
    ],
    ids=['login_refresh_required', 'login_token_load_error', 'no_region_error'],
)
async def test_proxy_client_connect_botocore_error(botocore_error, expected_hint):
    """Test connection converts RuntimeError wrapping a botocore error to MCPError without retry."""
    mock_transport = Mock(spec=ClientTransport)
    client = AWSMCPProxyClient(mock_transport)

    runtime_error = RuntimeError('Client failed to connect')
    runtime_error.__cause__ = botocore_error

    with patch(
        'mcp_proxy_for_aws.proxy.StatefulProxyClient._connect', side_effect=runtime_error
    ) as mock_connect:
        with patch.object(client, '_disconnect', new_callable=AsyncMock) as mock_disconnect:
            with pytest.raises(MCPError) as exc_info:
                await client._connect()

    assert exc_info.value.error.code == -32603
    assert exc_info.value.error.message == str(botocore_error)
    assert expected_hint in exc_info.value.error.message
    assert mock_connect.call_count == 1
    mock_disconnect.assert_not_called()
