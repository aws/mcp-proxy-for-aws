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
from collections.abc import Awaitable, Callable
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool
from typing import Sequence


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

            # Skip the tools with no readOnlyHint=True annotation
            read_only_hint = getattr(annotations, 'readOnlyHint', False)
            if not read_only_hint:
                # Skip tools that don't have readOnlyHint=True
                self.logger.info('Skipping tool %s needing write permissions', tool.name)
                continue

            filtered_tools.append(tool)

        return filtered_tools
