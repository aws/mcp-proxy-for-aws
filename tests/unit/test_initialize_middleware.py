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
from mcp_proxy_for_aws.middleware.initialize_middleware import InitializeMiddleware
from unittest.mock import AsyncMock, Mock


def create_initialize_request(client_name: str) -> mt.InitializeRequest:
    """Create a real InitializeRequest object."""
    return mt.InitializeRequest(
        method='initialize',
        params=mt.InitializeRequestParams(
            protocolVersion='2024-11-05',
            capabilities=mt.ClientCapabilities(),
            clientInfo=mt.Implementation(name=client_name, version='1.0'),
        ),
    )


@pytest.mark.asyncio
async def test_on_initialize_connects_client():
    """Test that on_initialize calls client._connect()."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = mt.InitializeResult(
        protocolVersion='2024-11-05',
        capabilities=mt.ServerCapabilities(),
        serverInfo=mt.Implementation(name='backend-server', version='2.0'),
    )

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_init_options = Mock()
    mock_session = Mock()
    mock_session._init_options = mock_init_options
    mock_fastmcp_ctx = Mock()
    mock_fastmcp_ctx._session = mock_session

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')
    mock_context.fastmcp_context = mock_fastmcp_ctx

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    mock_factory.set_init_params.assert_called_once_with(mock_context.message)
    mock_factory.get_client.assert_called_once()
    mock_client._connect.assert_called_once()
    mock_call_next.assert_called_once_with(mock_context)

    # Verify init_options capabilities were overwritten with backend server info
    assert mock_init_options.capabilities == mt.ServerCapabilities()


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


@pytest.mark.asyncio
async def test_on_initialize_overwrites_init_options_with_backend_info():
    """Test that on_initialize overwrites session init_options with backend server info."""
    backend_capabilities = mt.ServerCapabilities(
        logging=mt.LoggingCapability(),
    )
    backend_result = mt.InitializeResult(
        protocolVersion='2024-11-05',
        capabilities=backend_capabilities,
        serverInfo=mt.Implementation(name='backend-mcp', version='3.1'),
    )

    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = backend_result

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_init_options = Mock()
    mock_init_options.server_name = 'proxy-name'
    mock_init_options.server_version = '1.0'
    mock_init_options.capabilities = mt.ServerCapabilities()
    mock_session = Mock()
    mock_session._init_options = mock_init_options
    mock_fastmcp_ctx = Mock()
    mock_fastmcp_ctx._session = mock_session

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')
    mock_context.fastmcp_context = mock_fastmcp_ctx

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    assert mock_init_options.capabilities == backend_capabilities


@pytest.mark.asyncio
async def test_on_initialize_disables_prompts_and_resources():
    """Test that prompts and resources capabilities are disabled even if backend supports them."""
    backend_capabilities = mt.ServerCapabilities(
        tools=mt.ToolsCapability(),
        prompts=mt.PromptsCapability(),
        resources=mt.ResourcesCapability(),
    )
    backend_result = mt.InitializeResult(
        protocolVersion='2024-11-05',
        capabilities=backend_capabilities,
        serverInfo=mt.Implementation(name='backend', version='1.0'),
    )

    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = backend_result

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_init_options = Mock()
    mock_session = Mock()
    mock_session._init_options = mock_init_options
    mock_fastmcp_ctx = Mock()
    mock_fastmcp_ctx._session = mock_session

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')
    mock_context.fastmcp_context = mock_fastmcp_ctx

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    assert mock_init_options.capabilities.prompts is not None
    assert mock_init_options.capabilities.resources is not None
    assert mock_init_options.capabilities.tools is not None


@pytest.mark.asyncio
async def test_on_initialize_skips_overwrite_when_no_session():
    """Test that overwrite is skipped when no session is available."""
    mock_client = Mock()
    mock_client._connect = AsyncMock()
    mock_client.initialize_result = mt.InitializeResult(
        protocolVersion='2024-11-05',
        capabilities=mt.ServerCapabilities(),
        serverInfo=mt.Implementation(name='backend', version='1.0'),
    )

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')
    mock_context.fastmcp_context = None

    mock_call_next = AsyncMock()

    # Should not raise, just skip overwrite
    await middleware.on_initialize(mock_context, mock_call_next)
    mock_call_next.assert_called_once_with(mock_context)
