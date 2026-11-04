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

import asyncio
import mcp.types as mt
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import FastMCPTransport
from fastmcp.server.providers.proxy import FastMCPProxy
from mcp import MCPError
from mcp_proxy_for_aws.context import get_client_capabilities, get_client_info, set_client_info
from mcp_proxy_for_aws.middleware.initialize_middleware import InitializeMiddleware
from mcp_proxy_for_aws.proxy import AWSMCPProxyClient, AWSMCPProxyClientFactory
from mcp_proxy_for_aws.sigv4_helper import _build_user_agent
from unittest.mock import AsyncMock, Mock, patch


PROXY_INSTRUCTIONS = 'PROXY PLACEHOLDER INSTRUCTIONS'


def create_initialize_request(client_name: str) -> mt.InitializeRequest:
    """Create a real InitializeRequest object."""
    return mt.InitializeRequest(
        method='initialize',
        params=mt.InitializeRequestParams(
            protocol_version='2024-11-05',
            capabilities=mt.ClientCapabilities(),
            client_info=mt.Implementation(name=client_name, version='1.0'),
        ),
    )


@pytest.mark.asyncio
async def test_on_initialize_connects_client():
    """Test that on_initialize calls client._connect()."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = mt.InitializeResult(
        protocol_version='2024-11-05',
        capabilities=mt.ServerCapabilities(),
        server_info=mt.Implementation(name='backend-server', version='2.0'),
    )

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    # A backend that advertises no instructions must leave the proxy's own alone.
    mock_client.instructions = None

    middleware = InitializeMiddleware(mock_factory)

    mock_fastmcp_ctx = Mock()
    mock_fastmcp_ctx.fastmcp.instructions = 'proxy instructions'

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')
    mock_context.fastmcp_context = mock_fastmcp_ctx

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    mock_factory.set_init_params.assert_called_once_with(mock_context.message)
    mock_factory.get_client.assert_called_once()
    mock_client._connect.assert_called_once()
    mock_call_next.assert_called_once_with(mock_context)

    # Backend sent no instructions, so the proxy's own are untouched. Capabilities are not
    # copied here; the proxy negotiates them (see test_backend_capabilities_are_proxied).
    assert mock_fastmcp_ctx.fastmcp.instructions == 'proxy instructions'


@pytest.mark.asyncio
async def test_on_initialize_stores_client_capabilities():
    """Test that on_initialize stores the client's capabilities before connecting."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = None

    mock_factory = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')

    call_order = []
    mock_client._connect.side_effect = lambda: call_order.append('connect')

    def record_capabilities(capabilities):
        call_order.append(('set_client_capabilities', capabilities))

    with patch(
        'mcp_proxy_for_aws.middleware.initialize_middleware.set_client_capabilities',
        side_effect=record_capabilities,
    ):
        await middleware.on_initialize(mock_context, AsyncMock())

    assert call_order == [
        ('set_client_capabilities', mock_context.message.params.capabilities),
        'connect',
    ]


@pytest.mark.asyncio
async def test_on_initialize_fails_if_connect_fails():
    """Test that on_initialize raises exception if _connect() fails."""
    mock_client = Mock()
    mock_client._connect = AsyncMock(side_effect=Exception('Connection failed'))

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')

    mock_call_next = AsyncMock()

    with pytest.raises(Exception, match='Connection failed'):
        await middleware.on_initialize(mock_context, mock_call_next)

    mock_call_next.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'client_name',
    [
        'Kiro CLI',
        'kiro cli',
        'KIRO CLI',
        'Amazon Q Dev CLI',
        'amazon q dev cli',
        'Q DEV CLI',
    ],
)
async def test_on_initialize_skips_connect_for_special_clients(client_name):
    """Test that on_initialize skips _connect() for Kiro CLI and Q Dev CLI."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = None

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_context = Mock()
    mock_context.message = create_initialize_request(client_name)

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    mock_client._connect.assert_not_called()
    mock_call_next.assert_called_once_with(mock_context)
    assert get_client_capabilities() == mock_context.message.params.capabilities


@pytest.mark.parametrize(
    'mode, backend_instructions, expected',
    [
        # Both modes must report the backend's instructions, though they read them at
        # different moments -- see InitializeMiddleware._publish_instructions.
        ('legacy', 'BACKEND SAYS HELLO', 'BACKEND SAYS HELLO'),
        ('auto', 'BACKEND SAYS HELLO', 'BACKEND SAYS HELLO'),
        # A backend that sends none must not blank out the proxy's own.
        ('legacy', None, PROXY_INSTRUCTIONS),
        ('auto', None, PROXY_INSTRUCTIONS),
    ],
)
@pytest.mark.asyncio
async def test_backend_instructions_reach_the_client(mode, backend_instructions, expected):
    """The client is told the backend's instructions, not the proxy's placeholder.

    Driven through a real FastMCPProxy and Client: a mocked session would report success
    whether or not the instructions were actually forwarded.
    """
    backend = FastMCP('backend-server', instructions=backend_instructions)

    @backend.tool()
    def backend_tool() -> str:
        """A backend tool."""
        return 'ok'

    factory = AWSMCPProxyClientFactory(FastMCPTransport(backend))
    proxy = FastMCPProxy(
        client_factory=factory,
        name='MCP Proxy for AWS',
        instructions=PROXY_INSTRUCTIONS,
    )
    proxy.add_middleware(InitializeMiddleware(factory))

    async with Client(proxy, mode=mode) as client:
        assert client.instructions == expected
        # The backend is still proxied normally.
        assert [tool.name for tool in await client.list_tools()] == ['backend_tool']


@pytest.mark.parametrize(
    'client_name, initialize_fails',
    [
        # These clients cannot report a JSON-RPC error raised during initialize, so a backend
        # that cannot be reached must not fail it.
        ('Kiro CLI', False),
        ('Amazon Q Dev CLI', False),
        # Everyone else gets the failure at connect time instead of mid-tool-call.
        ('some-other-client', True),
    ],
)
@pytest.mark.asyncio
async def test_unreachable_backend_fails_initialize_only_for_clients_that_can_report_it(
    monkeypatch, client_name, initialize_fails
):
    """An unreachable backend fails `initialize` unless the client cannot handle that failure.

    Driven through the real proxy stack with a backend that refuses every connection. Reading
    whether the backend is connected afterwards would not do: the proxy's own metadata
    forwarding connects it once `initialize` has been answered, and swallows connect errors.
    """
    backend = FastMCP('backend-server')
    refusal = MCPError(code=mt.INTERNAL_ERROR, message='backend refused the connection')

    async def refuse(self, retry=0):
        raise refusal

    monkeypatch.setattr(AWSMCPProxyClient, '_connect', refuse)

    factory = AWSMCPProxyClientFactory(FastMCPTransport(backend))
    proxy = FastMCPProxy(client_factory=factory, name='MCP Proxy for AWS')
    proxy.add_middleware(InitializeMiddleware(factory))
    client = Client(
        proxy,
        mode='legacy',
        client_info=mt.Implementation(name=client_name, version='1.0'),
    )

    set_client_info(None)
    try:
        if initialize_fails:
            with pytest.raises(MCPError, match='backend refused the connection'):
                async with client:
                    pass
        else:
            async with client:
                assert client.is_connected()
    finally:
        set_client_info(None)


@pytest.mark.asyncio
async def test_unreachable_backend_is_reported_to_a_client_that_sends_no_handshake(monkeypatch):
    """Without a handshake, the client has to be told why the backend is unreachable.

    `server/discover` must still succeed so the client does not take the proxy for a legacy
    server and fall back to a handshake it would be refused; the real error then comes back on
    the first request. Silence here would look like a backend with no tools.
    """
    backend = FastMCP('backend-server')

    async def refuse(self, retry=0):
        raise MCPError(code=mt.INTERNAL_ERROR, message='backend refused the connection')

    monkeypatch.setattr(AWSMCPProxyClient, '_connect', refuse)

    factory = AWSMCPProxyClientFactory(FastMCPTransport(backend))
    proxy = FastMCPProxy(client_factory=factory, name='MCP Proxy for AWS')
    proxy.add_middleware(InitializeMiddleware(factory))

    set_client_info(None)
    try:
        async with Client(
            proxy,
            mode='auto',
            client_info=mt.Implementation(name='some-client', version='1.0'),
        ) as client:
            for _ in range(2):  # the failure repeats until the backend can be reached
                with pytest.raises(MCPError, match='backend refused the connection'):
                    await client.list_tools()
    finally:
        set_client_info(None)


@pytest.mark.asyncio
async def test_on_request_retries_the_connect_until_it_works():
    """A failed connect leaves the backend unconnected, so the next request tries again."""
    mock_client = Mock()
    mock_client._connect = AsyncMock(side_effect=[MCPError(code=-32603, message='down'), None])
    mock_client.instructions = None
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    call_next = AsyncMock(return_value='result')

    discover = Mock()
    discover.method = 'server/discover'
    discover.fastmcp_context = None

    tools = Mock()
    tools.method = 'tools/list'
    tools.fastmcp_context = None

    # The era probe is let through without the backend...
    assert await middleware.on_request(discover, call_next) == 'result'
    assert mock_client._connect.await_count == 1

    # ...and the connect is attempted again on the next request, then not repeated.
    assert await middleware.on_request(tools, call_next) == 'result'
    assert await middleware.on_request(tools, call_next) == 'result'
    assert mock_client._connect.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_first_requests_connect_the_backend_once():
    """Requests racing to be first must not each open their own connection."""
    mock_client = Mock()
    mock_client.instructions = None

    async def slow_connect():
        await asyncio.sleep(0.05)

    mock_client._connect = AsyncMock(side_effect=slow_connect)
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    context = Mock()
    context.method = 'tools/list'
    context.fastmcp_context = None

    await asyncio.gather(
        *(middleware.on_request(context, AsyncMock(return_value='result')) for _ in range(5))
    )

    mock_client._connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_request_raises_a_failed_connect_on_anything_but_discover():
    """Only the era probe is spared: any other request gets the real error."""
    mock_client = Mock()
    mock_client._connect = AsyncMock(side_effect=MCPError(code=-32603, message='down'))
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    context = Mock()
    context.method = 'tools/list'
    context.fastmcp_context = None
    call_next = AsyncMock(return_value='result')

    with pytest.raises(MCPError, match='down'):
        await middleware.on_request(context, call_next)

    call_next.assert_not_awaited()


@pytest.mark.parametrize('mode', ['legacy', 'auto'])
@pytest.mark.asyncio
async def test_client_info_is_captured_either_way(mode):
    """The client's identity is recorded either way, since the User-Agent is built from it.

    A handshake carries it as an opening message; without one it rides along with every
    request instead, so capturing it in on_initialize alone would silently drop it.
    """
    backend = FastMCP('backend-server')

    @backend.tool()
    def backend_tool() -> str:
        """A backend tool."""
        return 'ok'

    factory = AWSMCPProxyClientFactory(FastMCPTransport(backend))
    proxy = FastMCPProxy(client_factory=factory, name='MCP Proxy for AWS')
    proxy.add_middleware(InitializeMiddleware(factory))

    set_client_info(None)
    try:
        async with Client(
            proxy,
            mode=mode,
            client_info=mt.Implementation(name='probe-client', version='9.9'),
        ) as client:
            await client.list_tools()
            captured = get_client_info()
            assert captured is not None
            assert (captured.name, captured.version) == ('probe-client', '9.9')

            # The capture only matters because the backend's User-Agent is built from it, so
            # assert the value the backend would actually see rather than just the stored one.
            assert 'probe-client/9.9' in _build_user_agent(disable_telemetry=False)
            assert 'probe-client' not in _build_user_agent(disable_telemetry=True)
    finally:
        set_client_info(None)


@pytest.mark.parametrize('mode', ['legacy', 'auto'])
@pytest.mark.asyncio
async def test_backend_capabilities_are_proxied(mode):
    """Everything the backend exposes -- tools, resources, prompts -- is reachable through the proxy."""
    backend = FastMCP('backend-server')

    @backend.tool()
    def backend_tool() -> str:
        """A backend tool."""
        return 'ok'

    @backend.resource('resource://greeting')
    def greeting() -> str:
        """A backend resource."""
        return 'hello'

    @backend.prompt()
    def backend_prompt() -> str:
        """A backend prompt."""
        return 'prompt body'

    factory = AWSMCPProxyClientFactory(FastMCPTransport(backend))
    proxy = FastMCPProxy(client_factory=factory, name='MCP Proxy for AWS')
    proxy.add_middleware(InitializeMiddleware(factory))

    async with Client(proxy, mode=mode) as client:
        assert [tool.name for tool in await client.list_tools()] == ['backend_tool']
        assert [str(res.uri) for res in await client.list_resources()] == ['resource://greeting']
        assert [prompt.name for prompt in await client.list_prompts()] == ['backend_prompt']


@pytest.mark.asyncio
async def test_on_request_connects_backend_when_no_handshake_ran():
    """A handshake-free connection never calls on_initialize, so on_request must connect.

    Otherwise the backend stays unconnected until the first tool call, turning a bad endpoint
    into a mid-call failure instead of a connect-time one.
    """
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    context = Mock()
    context.method = 'server/discover'
    call_next = AsyncMock(return_value='result')

    assert await middleware.on_request(context, call_next) == 'result'

    mock_client._connect.assert_awaited_once()
    call_next.assert_awaited_once_with(context)


@pytest.mark.asyncio
async def test_on_request_leaves_the_initialize_connect_to_on_initialize():
    """on_request runs ahead of on_initialize, so it must not connect on `initialize` itself.

    Connecting here would pre-empt the handshake path and the per-client opt-outs it applies.
    """
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    context = Mock()
    context.method = 'initialize'
    call_next = AsyncMock(return_value='result')

    assert await middleware.on_request(context, call_next) == 'result'

    mock_client._connect.assert_not_awaited()
    call_next.assert_awaited_once_with(context)


@pytest.mark.asyncio
async def test_on_request_connects_backend_only_once():
    """The fallback runs on the first request only, not on every subsequent one."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(factory)
    context = Mock()
    context.method = 'tools/list'

    for _ in range(3):
        await middleware.on_request(context, AsyncMock(return_value='result'))

    mock_client._connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_request_does_not_reconnect_after_handshake():
    """After a handshake, on_initialize already connected, so on_request must not repeat it."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = None
    factory = Mock()
    factory.get_client = AsyncMock(return_value=mock_client)
    factory.set_init_params = Mock()

    middleware = InitializeMiddleware(factory)

    init_context = Mock()
    init_context.message = create_initialize_request('test-client')
    init_context.fastmcp_context = None
    await middleware.on_initialize(init_context, AsyncMock(return_value=None))
    assert mock_client._connect.await_count == 1

    request_context = Mock()
    request_context.method = 'tools/list'
    await middleware.on_request(request_context, AsyncMock(return_value='result'))

    # Still one: the handshake path already owns the connect.
    assert mock_client._connect.await_count == 1
