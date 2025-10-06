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

"""MCP Proxy Manager for handling proxy content integration."""

import logging
from fastmcp.server.middleware.error_handling import RetryMiddleware
from fastmcp.server.server import FastMCP


class McpProxyManager:
    """Manages the integration of proxy content (tools, resources, prompts) into MCP servers."""

    logger = logging.getLogger(__name__)

    def __init__(self, target_mcp: FastMCP, read_only: bool):
        """Initialize the MCP Proxy Manager.

        Args:
            target_mcp: The target MCP server to add content to
            read_only: If true, disable tools that require write permissions OR that do not have `readOnlyHint` set.
            rate_limit: Maximum requests per second for rate limiting (0 to disable rate limiting)
        """
        self.target_mcp = target_mcp
        self.read_only = read_only

    async def add_proxy_content(self, proxy: FastMCP, retries: int) -> None:
        """Add tools, resources, and prompts from proxy to MCP server.

        Args:
            proxy: The proxy FastMCP instance to get content from
            retries: Number of retry attempts for failed requests (0 to disable retries)

        Raises:
            Exception: If tools cannot be retrieved or added
        """
        if retries:
            self._add_retry_middleware(proxy, retries)

        try:
            await self._add_tools(proxy)
            await self._add_resources(proxy)
            await self._add_prompts(proxy)

            self.logger.info('Successfully added proxy content to MCP server')

        except Exception as e:
            self.logger.error(f'Failed to add proxy content to MCP server: {e}')
            raise

    async def _add_tools(self, proxy: FastMCP) -> None:
        """Add tools from proxy to target MCP server.

        Args:
            proxy: The proxy FastMCP instance to get tools from

        Raises:
            Exception: If tools cannot be retrieved or added
        """
        tools = await proxy.get_tools()
        self.logger.info(f'Found {len(tools)} tools in proxy')

        for tool_name, tool in tools.items():
            # Check the tool annotations and disable if needed
            annotations = tool.annotations
            if self.read_only:
                # In readOnly mode, skip the tools with no readOnlyHint=True annotation
                if annotations and not annotations.readOnlyHint or not annotations:
                    self.logger.info(f'Skipping tool {tool_name} needing write permissions')
                    continue

            self.target_mcp.add_tool(tool)

    async def _add_resources(self, proxy: FastMCP) -> None:
        """Add resources from proxy to target MCP server.

        Args:
            proxy: The proxy FastMCP instance to get resources from
        """
        try:
            resources = await proxy.get_resources()
            self.logger.info(f'Found {len(resources)} resources in proxy')

            for resource_uri, resource in resources.items():
                self.target_mcp.add_resource(resource)
                self.logger.debug(f'Added resource: {resource_uri}')

        except AttributeError:
            # Proxy doesn't have resources, which is fine
            self.logger.debug("Proxy doesn't have resources method")
        except Exception as e:
            self.logger.warning(f'Failed to get resources from proxy: {e}')

    async def _add_prompts(self, proxy: FastMCP) -> None:
        """Add prompts from proxy to target MCP server.

        Args:
            proxy: The proxy FastMCP instance to get prompts from
        """
        try:
            prompts = await proxy.get_prompts()
            self.logger.info(f'Found {len(prompts)} prompts in proxy')

            for prompt_name, prompt in prompts.items():
                self.target_mcp.add_prompt(prompt)
                self.logger.debug(f'Added prompt: {prompt_name}')

        except AttributeError:
            # Proxy doesn't have prompts, which is fine
            self.logger.debug("Proxy doesn't have prompts method")
        except Exception as e:
            self.logger.warning(f'Failed to get prompts from proxy: {e}')

    def _add_retry_middleware(self, mcp: FastMCP, num_retries: int) -> None:
        """Add retry with exponential backoff middleware to target MCP server.

        Args:
            mcp: The FastMCP instance to add exponential backoff to
            num_retries: Number of retry attempts
        """
        self.logger.info('Adding retry middleware')
        mcp.add_middleware(RetryMiddleware(num_retries))
