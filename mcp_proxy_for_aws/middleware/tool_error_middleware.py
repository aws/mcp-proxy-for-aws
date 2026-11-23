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
import anyio.to_thread
import httpx2
import logging
import mcp.types as mt
from collections.abc import Callable
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp import MCPError


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
        check_credentials: Callable[[], None] | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            tool_call_timeout: Maximum seconds a tool call may take before being
                cancelled.
            check_credentials: Called after a failed tool call; raises when the AWS
                credentials used for signing cannot be resolved.
        """
        super().__init__()
        self._tool_call_timeout = tool_call_timeout
        self._check_credentials = check_credentials

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
            credential_error = await self._credential_error()
            if credential_error is not None:
                message = (
                    f'Tool call {tool_name!r} failed because AWS credentials could not be resolved:'
                    f' {credential_error}. Please refresh your credentials and retry.'
                    ' The proxy will automatically use the new credentials on the next request.'
                )
            elif self._is_credential_error(e):
                message = (
                    f'Tool call {tool_name!r} failed due to expired or invalid AWS credentials.'
                    ' Please refresh your credentials and retry.'
                    ' The proxy will automatically use the new credentials on the next request.'
                )
            raise ToolError(message) from e

    async def _credential_error(self) -> str | None:
        """Return why credentials cannot be resolved, or None when they can.

        A failure to sign surfaces far from its cause: the SDK reports the request as a
        closed connection, and a failed tool listing reports every tool as unknown.
        """
        if self._check_credentials is None:
            return None
        try:
            await anyio.to_thread.run_sync(self._check_credentials)
        except Exception as e:
            return str(e)
        return None

    @staticmethod
    def _is_credential_error(error: Exception) -> bool:
        """Check if the error is likely caused by expired or invalid credentials.

        Walks the exception chain (__cause__/__context__) because the
        error may be wrapped.  isinstance already respects the MRO, so
        subclasses are caught too.  The SDK reports a rejected request as an
        MCPError rather than an HTTPStatusError; the transport hook gives that
        error the HTTP status as its code.
        """
        current: BaseException | None = error
        while current is not None:
            if isinstance(current, httpx2.HTTPStatusError) and current.response.status_code in (
                401,
                403,
            ):
                return True
            if isinstance(current, MCPError) and current.code in (401, 403):
                return True
            if isinstance(current, ValueError) and 'credentials' in str(current).lower():
                return True
            current = current.__cause__ or current.__context__
        return False
