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

from fastmcp.server.middleware import Middleware, MiddlewareContext
import logging
from fastmcp.server.server import FastMCP
from fastmcp.tools.tool import Tool
from collections.abc import Callable, Awaitable

class ToolFilteringMiddleware(Middleware): 
    def __init__(self, read_only: bool, logger: logging.Logger | None = None):
        self.read_only = read_only 
        self.logger = logger or logging.getLogger("fastmcp.errors") 
    
    async def on_list_tools(self, context: MiddlewareContext, call_next: Callable[[MiddlewareContext], Awaitable[list[Tool]]]):
        # Get list of FastMCP Components
        tools = await call_next(context)
        filtered_tools = []
        for tool in tools:
            # Check the tool annotations and disable if needed
            annotations = tool.annotations
            if self.read_only:
                # In readOnly mode, skip the tools with no readOnlyHint=True annotation
                read_only_hint = getattr(annotations, 'readOnlyHint', False)
                if not read_only_hint:
                    # Skip tools that don't have readOnlyHint=True
                    self.logger.info(f'Skipping tool {tool.name} needing write permissions')
                    continue

            filtered_tools.append(tool)

        
        return filtered_tools
