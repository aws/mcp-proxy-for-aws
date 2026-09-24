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

import mcp.types as mt
import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.providers.proxy import FastMCPProxy
from mcp_proxy_for_aws.middleware.initialize_middleware import InitializeMiddleware
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, Mock


if TYPE_CHECKING:
    from mcp_proxy_for_aws.proxy import AWSMCPProxyClientFactory


PROXY_INSTRUCTIONS = 'PROXY PLACEHOLDER INSTRUCTIONS'


class _StubClientFactory:
    """Minimal stand-in for AWSMCPProxyClientFactory backed by an in-process server.

    Mirrors the real factory's contract -- one cached client, reachable via both `get_client()`
    and `__call__()` -- so the middleware under test drives a genuine proxy connection.
    """

    def __init__(self, server: FastMCP) -> None:
        self._server = server
        self._client: Client | None = None
        self.init_params = None

    def set_init_params(self, initialize_request) -> None:
        self.init_params = initialize_request

    async def get_client(self) -> Client:
        if self._client is None:
            self._client = Client(self._server)
        return self._client

    async def __call__(self) -> Client:
        return await self.get_client()


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

    # Backend sent no instructions, so the proxy's own are untouched. Capabilities are no
    # longer copied here at all; fastmcp 4's proxy negotiates them from the backend connection
    # (asserted end to end in test_backend_capabilities_are_proxied_on_both_eras).
    assert mock_fastmcp_ctx.fastmcp.instructions == 'proxy instructions'


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


@pytest.mark.parametrize(
    'mode, backend_instructions, expected',
    [
        # Both eras must end up reporting the backend's instructions, though they read them at
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

    Driven through a real FastMCPProxy and a real Client rather than mocks. The mock-based
    version of this test asserted against a `Mock` stand-in for a private SDK attribute
    (`ServerSession._init_options`) that SDK v2 removed outright, so it kept passing after the
    behaviour it covered had stopped working.
    """
    backend = FastMCP('backend-server', instructions=backend_instructions)

    @backend.tool()
    def backend_tool() -> str:
        """A backend tool."""
        return 'ok'

    factory = _StubClientFactory(backend)
    proxy = FastMCPProxy(
        client_factory=factory,
        name='MCP Proxy for AWS',
        instructions=PROXY_INSTRUCTIONS,
    )
    proxy.add_middleware(InitializeMiddleware(cast('AWSMCPProxyClientFactory', factory)))

    async with Client(proxy, mode=mode) as client:
        assert client.instructions == expected
        # The backend is still proxied normally.
        assert [tool.name for tool in await client.list_tools()] == ['backend_tool']


@pytest.mark.parametrize('mode', ['legacy', 'auto'])
@pytest.mark.asyncio
async def test_backend_capabilities_are_proxied_on_both_eras(mode):
    """Backend tools/prompts/resources reach the client without hand-copied capabilities.

    Earlier releases copied `InitializeResult.capabilities` onto the session by hand. fastmcp 4
    negotiates them from the backend connection instead, so this asserts the outcome that
    mattered: everything the backend exposes is reachable through the proxy.
    """
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

    factory = _StubClientFactory(backend)
    proxy = FastMCPProxy(client_factory=factory, name='MCP Proxy for AWS')
    proxy.add_middleware(InitializeMiddleware(cast('AWSMCPProxyClientFactory', factory)))

    async with Client(proxy, mode=mode) as client:
        assert [tool.name for tool in await client.list_tools()] == ['backend_tool']
        assert [str(res.uri) for res in await client.list_resources()] == ['resource://greeting']
        assert [prompt.name for prompt in await client.list_prompts()] == ['backend_prompt']


@pytest.mark.asyncio
async def test_on_request_connects_backend_when_no_handshake_ran():
    """The sessionless era never calls on_initialize, so on_request must connect the backend.

    Without this fallback the backend would stay unconnected until the first tool call, turning
    an unreachable or misconfigured endpoint into a mid-call failure instead of a connect-time
    one.
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
    """On the handshake eras on_initialize already connected, so on_request must not repeat it."""
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
