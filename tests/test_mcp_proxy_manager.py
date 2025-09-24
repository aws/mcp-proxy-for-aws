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

"""Tests for mcp_proxy_manager module."""

import pytest
from src.aws_mcp_proxy.mcp_proxy_manager import McpProxyManager
from fastmcp.server.server import FastMCP
from unittest.mock import AsyncMock, MagicMock


class TestMcpProxyManager:
    """Test cases for McpProxyManager class."""

    @pytest.fixture
    def mock_target_mcp(self):
        """Create a mock target MCP FastMCP instance."""
        mcp = MagicMock(spec=FastMCP)
        return mcp

    @pytest.fixture
    def mock_proxy(self):
        """Create a mock proxy FastMCP instance."""
        proxy = AsyncMock(spec=FastMCP)
        return proxy

    @pytest.fixture
    def mock_tool(self):
        """Create a mock tool."""
        tool = MagicMock()
        tool.name = 'test_tool'
        tool.title = 'Test Tool'
        tool.description = 'A test tool'
        tool.parameters = {}
        tool.output_schema = {}
        # Create a mock annotations object with readOnlyHint attribute
        annotations = MagicMock()
        annotations.readOnlyHint = True
        tool.annotations = annotations
        tool.tags = []
        tool.serializer = None
        tool.meta = {}
        tool.enabled = True
        tool.copy.return_value = tool
        return tool

    @pytest.fixture
    def mock_resource(self):
        """Create a mock resource."""
        resource = MagicMock()
        resource.copy.return_value = resource
        return resource

    @pytest.fixture
    def mock_prompt(self):
        """Create a mock prompt."""
        prompt = MagicMock()
        prompt.copy.return_value = prompt
        return prompt

    def test_init_default_allow_write(self, mock_target_mcp):
        """Test McpProxyManager initialization with default allow_write."""
        manager = McpProxyManager(mock_target_mcp)

        assert manager.target_mcp == mock_target_mcp
        assert manager.allow_write is False

    def test_init_custom_allow_write(self, mock_target_mcp):
        """Test McpProxyManager initialization with custom allow_write."""
        manager = McpProxyManager(mock_target_mcp, allow_write=True)

        assert manager.target_mcp == mock_target_mcp
        assert manager.allow_write is True

    @pytest.mark.asyncio
    async def test_add_proxy_content_success(
        self, mock_target_mcp, mock_proxy, mock_tool, mock_resource, mock_prompt
    ):
        """Test successful addition of all proxy content."""
        # Setup mock proxy responses
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.return_value = {'test_resource': mock_resource}
        mock_proxy.get_prompts.return_value = {'test_prompt': mock_prompt}

        manager = McpProxyManager(mock_target_mcp, allow_write=True)
        await manager.add_proxy_content(mock_proxy)

        # Verify all methods were called
        mock_proxy.get_tools.assert_called_once()
        mock_proxy.get_resources.assert_called_once()
        mock_proxy.get_prompts.assert_called_once()

        # Verify content was added to target MCP
        mock_target_mcp.add_tool.assert_called_once()
        mock_target_mcp.add_resource.assert_called_once_with(mock_resource)
        mock_target_mcp.add_prompt.assert_called_once_with(mock_prompt)

    @pytest.mark.asyncio
    async def test_add_tools_success(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test successful addition of tools."""
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp)
        await manager._add_tools(mock_proxy)

        mock_proxy.get_tools.assert_called_once()
        # We now create ProxyTool instances instead of copying
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_tools_skip_write_tools(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools requiring write permissions are skipped when allow_write=False."""
        # Setup tool with write permissions required
        annotations = MagicMock()
        annotations.readOnlyHint = False
        mock_tool.annotations = annotations

        mock_proxy.get_tools.return_value = {'write_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, allow_write=False)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_tools_allow_write_tools(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools requiring write permissions are added when allow_write=True."""
        # Setup tool with write permissions required
        annotations = MagicMock()
        annotations.readOnlyHint = False
        mock_tool.annotations = annotations

        mock_proxy.get_tools.return_value = {'write_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, allow_write=True)
        await manager._add_tools(mock_proxy)

        # Verify tool was added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_tools_readonly_tools(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that readonly tools are always added."""
        # Setup readonly tool
        annotations = MagicMock()
        annotations.readOnlyHint = True
        mock_tool.annotations = annotations

        mock_proxy.get_tools.return_value = {'readonly_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, allow_write=False)
        await manager._add_tools(mock_proxy)

        # Verify tool was added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_resources_success(self, mock_target_mcp, mock_proxy, mock_resource):
        """Test successful addition of resources."""
        mock_proxy.get_resources.return_value = {'test_resource': mock_resource}

        manager = McpProxyManager(mock_target_mcp)
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()
        mock_target_mcp.add_resource.assert_called_once_with(mock_resource)

    @pytest.mark.asyncio
    async def test_add_resources_no_resources_method(self, mock_target_mcp, mock_proxy):
        """Test handling when proxy doesn't have resources method."""
        mock_proxy.get_resources.side_effect = AttributeError('No resources method')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_resources_exception(self, mock_target_mcp, mock_proxy):
        """Test handling when get_resources raises an exception."""
        mock_proxy.get_resources.side_effect = Exception('Resource error')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_prompts_success(self, mock_target_mcp, mock_proxy, mock_prompt):
        """Test successful addition of prompts."""
        mock_proxy.get_prompts.return_value = {'test_prompt': mock_prompt}

        manager = McpProxyManager(mock_target_mcp)
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()
        mock_target_mcp.add_prompt.assert_called_once_with(mock_prompt)

    @pytest.mark.asyncio
    async def test_add_prompts_no_prompts_method(self, mock_target_mcp, mock_proxy):
        """Test handling when proxy doesn't have prompts method."""
        mock_proxy.get_prompts.side_effect = AttributeError('No prompts method')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_prompts_exception(self, mock_target_mcp, mock_proxy):
        """Test handling when get_prompts raises an exception."""
        mock_proxy.get_prompts.side_effect = Exception('Prompt error')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_proxy_content_tools_exception_propagates(self, mock_target_mcp, mock_proxy):
        """Test that exceptions from _add_tools are propagated."""
        mock_proxy.get_tools.side_effect = Exception('Tools error')

        manager = McpProxyManager(mock_target_mcp)

        with pytest.raises(Exception, match='Tools error'):
            await manager.add_proxy_content(mock_proxy)

    @pytest.mark.asyncio
    async def test_add_proxy_content_resources_exception_handled(
        self, mock_target_mcp, mock_proxy, mock_tool
    ):
        """Test that exceptions from _add_resources don't stop the process."""
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.side_effect = Exception('Resource error')
        mock_proxy.get_prompts.side_effect = AttributeError('No prompts')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager.add_proxy_content(mock_proxy)

        # Verify tools were still added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_proxy_content_prompts_exception_handled(
        self, mock_target_mcp, mock_proxy, mock_tool
    ):
        """Test that exceptions from _add_prompts don't stop the process."""
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.side_effect = AttributeError('No resources')
        mock_proxy.get_prompts.side_effect = Exception('Prompt error')

        manager = McpProxyManager(mock_target_mcp)
        # Should not raise an exception
        await manager.add_proxy_content(mock_proxy)

        # Verify tools were still added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_tools_no_annotations(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools with no annotations are skipped when allow_write=False."""
        # Setup tool with no annotations
        mock_tool.annotations = None

        mock_proxy.get_tools.return_value = {'no_annotations_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, allow_write=False)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_tools_empty_annotations(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools with empty annotations are skipped when allow_write=False."""
        # Setup tool with empty annotations
        mock_tool.annotations = {}

        mock_proxy.get_tools.return_value = {'empty_annotations_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, allow_write=False)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()
