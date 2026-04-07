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

import anyio
import httpx
import logging
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult


logger = logging.getLogger(__name__)


class _FailedToolResult(ToolResult):
    """A ToolResult that signals an error via the MCP isError flag."""

    def to_mcp_result(self) -> mt.CallToolResult:
        return mt.CallToolResult(content=self.content, isError=True)


class ToolErrorMiddleware(Middleware):
    """Middleware that ensures tool calls never hang and always return a response.

    Implements two layers of protection:
    1. Timeout — bounds how long a tool call can take, breaking any hang.
    2. Error propagation — catches any error and returns it as a ToolResult
       so the agent always gets a response.

    Reconnection is handled automatically by fastmcp on every tool call.
    """

    def __init__(
        self,
        tool_call_timeout: float | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            tool_call_timeout: Maximum seconds a tool call may take before being
                cancelled. None means no timeout (not recommended).
        """
        super().__init__()
        self._tool_call_timeout = tool_call_timeout

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Wrap tool calls with timeout and error handling."""
        try:
            with anyio.fail_after(self._tool_call_timeout):
                return await call_next(context)
        except Exception as e:
            tool_name = context.message.name
            logger.error('Tool call %r failed: %s.', tool_name, e)
            message = f'Tool call {tool_name!r} failed: {e}. Please retry.'
            if self._is_credential_error(e):
                message += (
                    ' This may be caused by expired or invalid AWS credentials.'
                    ' Consider using long-lived credentials such as an AWS profile'
                    ' (--profile) or IAM Identity Center (aws sso login).'
                )
            return self._error_result(message)

    @staticmethod
    def _is_credential_error(error: Exception) -> bool:
        """Check if the error is likely caused by expired or invalid credentials."""
        return isinstance(error, httpx.HTTPStatusError) and error.response.status_code in (
            401,
            403,
        )

    @staticmethod
    def _error_result(message: str) -> ToolResult:
        return _FailedToolResult(
            content=[mt.TextContent(type='text', text=message)],
        )
