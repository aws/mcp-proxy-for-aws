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
import re
from collections.abc import Awaitable, Callable
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import Tool
from typing import Sequence


# Assumes AWS API naming conventions (get_/list_/describe_ = read-only).
# File upstream issue on awslabs/mcp for proper readOnlyHint annotations.

# Remote MCP servers may not set readOnlyHint=true for their tools,
# but tools with these naming patterns never mutate state.
_READ_ONLY_TOOL_PREFIXES = (
    re.compile(r'^(list|read|search|get|describe|retrieve|recommend)_'),
)

# Reserved for future edge cases where a tool name matches the heuristic
# but is actually mutating — override here to force it as write-only.
_HEURISTIC_DENY_LIST: set[str] = set()


class ToolFilteringMiddleware(Middleware):
    """Middleware to filter tools based on read only flag."""

    def __init__(self, read_only: bool, logger: logging.Logger | None = None):
        """Initialize the middleware."""
        self.read_only = read_only
        self.logger = logger or logging.getLogger(__name__)

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Sequence[Tool]]],
    ):
        """Filter tools based on read only flag."""
        # Get list of FastMCP Components
        tools = await call_next(context)
        self.logger.info('Filtering tools for read only: %s', self.read_only)

        # If not read only, return the list of tools as is
        if not self.read_only:
            return tools

        filtered_tools = []
        for tool in tools:
            # Check the tool annotations and disable if needed
            annotations = tool.annotations

            # Skip the tools with no readOnlyHint=True annotation,
            # unless the tool name is inherently read-only
            read_only_hint = getattr(annotations, 'readOnlyHint', False)
            if not read_only_hint:
                # Check if the tool name matches a read-only prefix pattern
                name_is_read_only = any(
                    read_only_prefix.match(tool.name)
                    for read_only_prefix in _READ_ONLY_TOOL_PREFIXES
                )
                if not name_is_read_only:
                    # Skip tools that don't have readOnlyHint=True and
                    # whose name doesn't indicate a read-only operation
                    self.logger.info('Skipping tool %s needing write permissions', tool.name)
                    continue

            filtered_tools.append(tool)

        return filtered_tools
