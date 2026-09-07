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
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import MCPError
from mcp.types import ErrorData


@pytest.mark.asyncio
async def test_fastmcp_handles_initialize_error_from_middleware():
    """Test that fastmcp properly handles MCPError raised during initialization middleware.

    This validates that the fix from https://github.com/jlowin/fastmcp/pull/2531 works,
    ensuring that initialization errors are sent back to the client instead of crashing.
    """

    class InitializeErrorMiddleware(Middleware):
        """Middleware that raises an error during initialization."""

        async def on_initialize(
            self,
            context: MiddlewareContext[mt.InitializeRequest],
            call_next,
        ):
            raise MCPError.from_error_data(
                ErrorData(code=-1, message='Initialization failed from middleware')
            )

    server = FastMCP('test-server')
    server.add_middleware(InitializeErrorMiddleware())

    @server.tool()
    def test_tool() -> str:
        """A test tool."""
        return 'success'

    # mode='legacy' forces the initialize handshake; fastmcp 4 clients default to
    # 'auto', which negotiates via server/discover and never sends initialize.
    client = Client(server, mode='legacy')

    # The client should receive the error during initialization
    with pytest.raises(MCPError) as exc_info:
        async with client:
            pass

    # Verify the error contains our custom error data
    assert exc_info.value.error.code == -1
    assert exc_info.value.error.message == 'Initialization failed from middleware'


@pytest.mark.asyncio
async def test_fastmcp_handles_error_after_initialization_completes():
    """Test that fastmcp handles MCPError raised AFTER initialization completes.

    This validates that when an error is raised after call_next (when responder is already
    completed), fastmcp logs a warning but doesn't crash. The client receives the successful
    initialization response, not the error.

    This is a current limitation of fastmcp - errors raised after call_next cannot be sent
    to the client because the response has already been sent.
    """
    server = FastMCP('test-server')

    class PostInitializeErrorMiddleware(Middleware):
        """Middleware that raises an error AFTER initialization completes."""

        async def on_initialize(
            self,
            context: MiddlewareContext[mt.InitializeRequest],
            call_next,
        ):
            await call_next(context)
            # Raising error after call_next - responder is already completed
            raise MCPError.from_error_data(
                ErrorData(code=-1, message='Error after initialization')
            )

    server.add_middleware(PostInitializeErrorMiddleware())

    @server.tool()
    def test_tool() -> str:
        """A test tool."""
        return 'success'

    client = Client(server, mode='legacy')

    # Client should still initialize successfully because the error happens after response is sent
    async with client:
        # Verify we can list tools - initialization succeeded despite the error
        tools = await client.list_tools()
        assert len(tools) > 0
        assert tools[0].name == 'test_tool'
