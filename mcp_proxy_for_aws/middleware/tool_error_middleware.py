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
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult


logger = logging.getLogger(__name__)


class ToolErrorMiddleware(Middleware):
    """Middleware that ensures tool calls never hang and always return a response.

    Implements two layers of protection:
    1. Timeout — bounds how long a tool call can take, breaking any hang.
    2. Error propagation — catches any error and returns an error message
       to the agent so it always gets a response.

    Reconnection is handled automatically by fastmcp on every tool call.
    """

    def __init__(
        self,
        tool_call_timeout: float = 300.0,
    ) -> None:
        """Initialize the middleware.

        Args:
            tool_call_timeout: Maximum seconds a tool call may take before being
                cancelled.
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
                message = (
                    f'Tool call {tool_name!r} failed due to expired or invalid AWS credentials.'
                    ' Please refresh your credentials and retry.'
                    ' The proxy will automatically use the new credentials on the next request.'
                )
            raise ToolError(message) from e

    @staticmethod
    def _is_credential_error(error: Exception) -> bool:
        """Check if the error is likely caused by expired or invalid credentials."""
        # Walk the exception chain — the 401/403 may be wrapped
        current: BaseException | None = error
        while current is not None:
            if isinstance(current, httpx.HTTPStatusError) and current.response.status_code in (
                401,
                403,
            ):
                return True
            current = current.__cause__ if current.__cause__ else current.__context__
            # Avoid infinite loops on self-referencing chains
            if current is error:
                break

        # "Unknown tool" after a failed reconnect is almost always a credential issue
        error_str = str(error)
        if 'Unknown tool' in error_str or 'Unauthorized' in error_str:
            return True

        return False
