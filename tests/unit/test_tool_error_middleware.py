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

"""Unit tests for ToolErrorMiddleware."""

import anyio
import httpx
import mcp.types as mt
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools import ToolResult
from mcp import McpError
from mcp.types import ErrorData
from mcp_proxy_for_aws.middleware.tool_error_middleware import ToolErrorMiddleware
from unittest.mock import AsyncMock, Mock


def _make_context(tool_name: str = 'test_tool') -> MiddlewareContext[mt.CallToolRequestParams]:
    """Create a minimal MiddlewareContext for tool calls."""
    params = Mock(spec=mt.CallToolRequestParams)
    params.name = tool_name
    return MiddlewareContext[mt.CallToolRequestParams](
        message=params,
        type='request',
        method='tools/call',
    )


def _make_middleware(tool_call_timeout: float = 5.0) -> ToolErrorMiddleware:
    """Create a ToolErrorMiddleware with mocked dependencies."""
    return ToolErrorMiddleware(tool_call_timeout=tool_call_timeout)


class TestToolErrorMiddleware:
    """Test cases for ToolErrorMiddleware."""

    @pytest.mark.asyncio
    async def test_passes_through_on_success(self):
        """Successful tool calls pass through unchanged."""
        middleware = _make_middleware()
        expected = ToolResult(content=[mt.TextContent(type='text', text='ok')])
        call_next = AsyncMock(return_value=expected)
        context = _make_context()

        result = await middleware.on_call_tool(context, call_next)

        assert result is expected
        call_next.assert_awaited_once_with(context)

    @pytest.mark.asyncio
    async def test_catches_exception_raises_tool_error(self):
        """Exceptions are caught and raised as ToolError."""
        middleware = _make_middleware()
        call_next = AsyncMock(
            side_effect=McpError(ErrorData(code=-1, message='Connection closed'))
        )
        context = _make_context()

        with pytest.raises(ToolError, match='Connection closed'):
            await middleware.on_call_tool(context, call_next)

    @pytest.mark.asyncio
    async def test_timeout_raises_tool_error(self):
        """Tool calls that exceed the timeout raise a ToolError."""
        middleware = _make_middleware(tool_call_timeout=0.1)

        async def hang_forever(context: MiddlewareContext[mt.CallToolRequestParams]) -> ToolResult:
            await anyio.sleep(999)
            return ToolResult(content=[])  # unreachable

        context = _make_context(tool_name='slow_tool')

        with pytest.raises(ToolError, match='slow_tool'):
            await middleware.on_call_tool(context, hang_forever)

    @pytest.mark.asyncio
    async def test_credential_error_suggests_profile(self):
        """Credential errors suggest using long-lived credentials."""
        middleware = _make_middleware()
        response = Mock(spec=httpx.Response)
        response.status_code = 401
        call_next = AsyncMock(
            side_effect=httpx.HTTPStatusError('Unauthorized', request=Mock(), response=response)
        )
        context = _make_context()

        with pytest.raises(ToolError, match='expired or invalid AWS credentials') as exc_info:
            await middleware.on_call_tool(context, call_next)
        assert 'refresh your credentials' in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_non_credential_error_no_suggestion(self):
        """Non-credential errors do not suggest credential remediation."""
        middleware = _make_middleware()
        call_next = AsyncMock(side_effect=RuntimeError('transport died'))
        context = _make_context()

        with pytest.raises(ToolError) as exc_info:
            await middleware.on_call_tool(context, call_next)
        assert '--profile' not in str(exc_info.value)
