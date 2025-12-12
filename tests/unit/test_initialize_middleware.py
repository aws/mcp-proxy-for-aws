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

    mock_factory = Mock()
    mock_factory.set_init_params = Mock()
    mock_factory.get_client = AsyncMock(return_value=mock_client)

    middleware = InitializeMiddleware(mock_factory)

    mock_context = Mock()
    mock_context.message = create_initialize_request('test-client')

    mock_call_next = AsyncMock()

    await middleware.on_initialize(mock_context, mock_call_next)

    mock_factory.set_init_params.assert_called_once_with(mock_context.message)
    mock_factory.get_client.assert_called_once()
    mock_client._connect.assert_called_once()
    mock_call_next.assert_called_once_with(mock_context)


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
