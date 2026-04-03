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

"""Unit tests for ToolTimeoutMiddleware."""

import anyio
import httpx
import mcp.types as mt
import pytest
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.tool import ToolResult
from mcp import McpError
from mcp.types import ErrorData
from mcp_proxy_for_aws.middleware.tool_timeout_middleware import (
    ToolTimeoutMiddleware,
    _FailedToolResult,
)
from typing import Optional
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


def _make_middleware(tool_call_timeout: Optional[float] = 5.0) -> ToolTimeoutMiddleware:
    """Create a ToolTimeoutMiddleware with mocked dependencies."""
    middleware = ToolTimeoutMiddleware(
        tool_call_timeout=tool_call_timeout,
    )
    return middleware


def _get_text(result: ToolResult, index: int = 0) -> str:
    """Extract text from a ToolResult content item."""
    content = result.content[index]
    assert isinstance(content, mt.TextContent)
    return content.text


class TestToolTimeoutMiddleware:
    """Test cases for ToolTimeoutMiddleware."""

    @pytest.mark.asyncio
    async def test_passes_through_on_success(self):
        """Successful tool calls pass through unchanged."""
        middleware = _make_middleware()
        expected = ToolResult(content=[mt.TextContent(type='text', text='ok')])
        call_next = AsyncMock(return_value=expected)
        context = _make_context()

        result = await middleware.on_call_tool(context, call_next)

        assert result is expected
        assert not isinstance(result, _FailedToolResult)
        call_next.assert_awaited_once_with(context)

    @pytest.mark.asyncio
    async def test_catches_exception_returns_error_result(self):
        """Exceptions are caught and returned as error ToolResults."""
        middleware = _make_middleware()
        call_next = AsyncMock(
            side_effect=McpError(ErrorData(code=-1, message='Connection closed'))
        )
        context = _make_context()

        result = await middleware.on_call_tool(context, call_next)

        assert isinstance(result, _FailedToolResult)
        assert len(result.content) == 1
        text = _get_text(result)
        assert 'Connection closed' in text

    @pytest.mark.asyncio
    async def test_timeout_returns_error_result(self):
        """Tool calls that exceed the timeout return an error ToolResult."""
        middleware = _make_middleware(tool_call_timeout=0.1)

        async def hang_forever(context: MiddlewareContext[mt.CallToolRequestParams]) -> ToolResult:
            await anyio.sleep(999)
            return ToolResult(content=[])  # unreachable

        context = _make_context(tool_name='slow_tool')

        result = await middleware.on_call_tool(context, hang_forever)

        assert isinstance(result, _FailedToolResult)
        assert len(result.content) == 1
        text = _get_text(result)
        assert 'slow_tool' in text

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

        result = await middleware.on_call_tool(context, call_next)

        assert isinstance(result, _FailedToolResult)
        text = _get_text(result)
        assert 'expired or invalid AWS credentials' in text
        assert '--profile' in text

    @pytest.mark.asyncio
    async def test_non_credential_error_no_suggestion(self):
        """Non-credential errors do not suggest credential remediation."""
        middleware = _make_middleware()
        call_next = AsyncMock(side_effect=RuntimeError('transport died'))
        context = _make_context()

        result = await middleware.on_call_tool(context, call_next)

        assert isinstance(result, _FailedToolResult)
        text = _get_text(result)
        assert '--profile' not in text

    @pytest.mark.asyncio
    async def test_no_timeout_when_none(self):
        """When tool_call_timeout is None, no timeout is applied."""
        middleware = _make_middleware(tool_call_timeout=None)
        expected = ToolResult(content=[mt.TextContent(type='text', text='ok')])
        call_next = AsyncMock(return_value=expected)
        context = _make_context()

        result = await middleware.on_call_tool(context, call_next)

        assert result is expected
