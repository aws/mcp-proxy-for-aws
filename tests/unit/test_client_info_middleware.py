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

import pytest
from datetime import datetime
from fastmcp.server.middleware import MiddlewareContext
from mcp import types as mt
from mcp_proxy_for_aws.context import get_client_info, set_client_info
from mcp_proxy_for_aws.middleware.client_info import ClientInfoMiddleware


@pytest.fixture
def middleware():
    """Create a ClientInfoMiddleware instance."""
    return ClientInfoMiddleware()


@pytest.fixture
def mock_context_with_client_info():
    """Create a mock context with client_info."""
    params = mt.InitializeRequestParams(
        protocolVersion='2024-11-05',
        capabilities=mt.ClientCapabilities(),
        clientInfo=mt.Implementation(name='test-client', version='1.0.0'),
    )
    message = mt.InitializeRequest(
        method='initialize',
        params=params,
    )
    return MiddlewareContext(
        message=message,
        fastmcp_context=None,
        source='client',
        type='request',
        method='initialize',
        timestamp=datetime.now(),
    )


@pytest.mark.asyncio
async def test_captures_client_info(middleware, mock_context_with_client_info):
    """Test that middleware captures client_info from initialize request."""
    # Reset context variable
    set_client_info(None)

    async def call_next(ctx):
        pass

    await middleware.on_initialize(mock_context_with_client_info, call_next)

    # Verify client_info was captured
    info = get_client_info()
    assert info is not None
    assert info.name == 'test-client'
    assert info.version == '1.0.0'


@pytest.mark.asyncio
async def test_calls_next_middleware(middleware, mock_context_with_client_info):
    """Test that middleware calls the next middleware in chain."""
    called = False

    async def call_next(ctx):
        nonlocal called
        called = True

    await middleware.on_initialize(mock_context_with_client_info, call_next)

    assert called is True


@pytest.mark.asyncio
async def test_captures_different_client_info(middleware):
    """Test that middleware captures different client_info values."""
    # Reset context variable
    set_client_info(None)

    params = mt.InitializeRequestParams(
        protocolVersion='2024-11-05',
        capabilities=mt.ClientCapabilities(),
        clientInfo=mt.Implementation(name='another-client', version='2.5.3'),
    )
    message = mt.InitializeRequest(
        method='initialize',
        params=params,
    )
    context = MiddlewareContext(
        message=message,
        fastmcp_context=None,
        source='client',
        type='request',
        method='initialize',
        timestamp=datetime.now(),
    )

    async def call_next(ctx):
        pass

    await middleware.on_initialize(context, call_next)

    # Verify client_info was captured with correct values
    info = get_client_info()
    assert info is not None
    assert info.name == 'another-client'
    assert info.version == '2.5.3'
