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

import logging
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult
from typing_extensions import override


debug_logger = logging.getLogger('mcp-proxy-debug')


class DebugLoggingMiddleware(Middleware):
    """Middleware that logs tools/call requests before FastMCP processes them."""

    @override
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name = context.message.name
        arg_keys = list((context.message.arguments or {}).keys())
        debug_logger.debug(
            '[PROXY-DEBUG] DebugLoggingMiddleware | received tools/call request | tool=%s, arg_keys=%s',
            tool_name,
            arg_keys,
        )
        try:
            result = await call_next(context)
            debug_logger.debug(
                '[PROXY-DEBUG] DebugLoggingMiddleware | tools/call completed | tool=%s, result_type=%s',
                tool_name,
                type(result).__name__,
            )
            return result
        except Exception as e:
            debug_logger.debug(
                '[PROXY-DEBUG] DebugLoggingMiddleware | tools/call failed | tool=%s, error=%s: %s',
                tool_name,
                type(e).__name__,
                e,
            )
            raise
