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
from aws_mcp_proxy.mcp_proxy_manager import McpProxyManager
from fastmcp.server.middleware.error_handling import RetryMiddleware
from fastmcp.server.server import FastMCP
from unittest.mock import AsyncMock, MagicMock


class TestMcpProxyManager:
    """Test cases for McpProxyManager class."""

    @pytest.fixture
    def mock_target_mcp(self):
        """Create a mock target MCP FastMCP instance."""
        mcp = MagicMock(spec=FastMCP)
        mcp.middleware = None  # Initialize middleware attribute
        return mcp

    @pytest.fixture
    def mock_proxy(self):
        """Create a mock proxy FastMCP instance."""
        proxy = AsyncMock(spec=FastMCP)
        proxy.middleware = None  # Initialize middleware attribute
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

    def test_init_default_read_only(self, mock_target_mcp):
        """Test McpProxyManager initialization with default read_only."""
        manager = McpProxyManager(mock_target_mcp, False)

        assert manager.target_mcp == mock_target_mcp
        assert manager.read_only is False

    def test_init_custom_read_only(self, mock_target_mcp):
        """Test McpProxyManager initialization with custom read_only."""
        manager = McpProxyManager(mock_target_mcp, read_only=True)

        assert manager.target_mcp == mock_target_mcp
        assert manager.read_only is True

    @pytest.mark.asyncio
    async def test_add_proxy_content_success(
        self, mock_target_mcp, mock_proxy, mock_tool, mock_resource, mock_prompt
    ):
        """Test successful addition of all proxy content."""
        # Setup mock proxy responses
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.return_value = {'test_resource': mock_resource}
        mock_proxy.get_prompts.return_value = {'test_prompt': mock_prompt}

        manager = McpProxyManager(mock_target_mcp, read_only=True)
        await manager.add_proxy_content(mock_proxy, 0)

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

        manager = McpProxyManager(mock_target_mcp, False)
        await manager._add_tools(mock_proxy)

        mock_proxy.get_tools.assert_called_once()
        # We now create ProxyTool instances instead of copying
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_tools_skip_write_tools(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools requiring write permissions are skipped when read_only=True."""
        # Setup tool with write permissions required
        annotations = MagicMock()
        annotations.readOnlyHint = False
        mock_tool.annotations = annotations

        mock_proxy.get_tools.return_value = {'write_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, read_only=True)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_tools_not_read_only_tools(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools requiring write permissions are added when read_only=False."""
        # Setup tool with write permissions required
        annotations = MagicMock()
        annotations.readOnlyHint = False
        mock_tool.annotations = annotations

        mock_proxy.get_tools.return_value = {'write_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, read_only=False)
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

        manager = McpProxyManager(mock_target_mcp, read_only=True)
        await manager._add_tools(mock_proxy)

        # Verify tool was added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_resources_success(self, mock_target_mcp, mock_proxy, mock_resource):
        """Test successful addition of resources."""
        mock_proxy.get_resources.return_value = {'test_resource': mock_resource}

        manager = McpProxyManager(mock_target_mcp, False)
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()
        mock_target_mcp.add_resource.assert_called_once_with(mock_resource)

    @pytest.mark.asyncio
    async def test_add_resources_no_resources_method(self, mock_target_mcp, mock_proxy):
        """Test handling when proxy doesn't have resources method."""
        mock_proxy.get_resources.side_effect = AttributeError('No resources method')

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_resources_exception(self, mock_target_mcp, mock_proxy):
        """Test handling when get_resources raises an exception."""
        mock_proxy.get_resources.side_effect = Exception('Resource error')

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager._add_resources(mock_proxy)

        mock_proxy.get_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_prompts_success(self, mock_target_mcp, mock_proxy, mock_prompt):
        """Test successful addition of prompts."""
        mock_proxy.get_prompts.return_value = {'test_prompt': mock_prompt}

        manager = McpProxyManager(mock_target_mcp, False)
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()
        mock_target_mcp.add_prompt.assert_called_once_with(mock_prompt)

    @pytest.mark.asyncio
    async def test_add_prompts_no_prompts_method(self, mock_target_mcp, mock_proxy):
        """Test handling when proxy doesn't have prompts method."""
        mock_proxy.get_prompts.side_effect = AttributeError('No prompts method')

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_prompts_exception(self, mock_target_mcp, mock_proxy):
        """Test handling when get_prompts raises an exception."""
        mock_proxy.get_prompts.side_effect = Exception('Prompt error')

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager._add_prompts(mock_proxy)

        mock_proxy.get_prompts.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_proxy_content_tools_exception_propagates(self, mock_target_mcp, mock_proxy):
        """Test that exceptions from _add_tools are propagated."""
        mock_proxy.get_tools.side_effect = Exception('Tools error')

        manager = McpProxyManager(mock_target_mcp, False)

        with pytest.raises(Exception, match='Tools error'):
            await manager.add_proxy_content(mock_proxy, 0)

    @pytest.mark.asyncio
    async def test_add_proxy_content_resources_exception_handled(
        self, mock_target_mcp, mock_proxy, mock_tool
    ):
        """Test that exceptions from _add_resources don't stop the process."""
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.side_effect = Exception('Resource error')
        mock_proxy.get_prompts.side_effect = AttributeError('No prompts')

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager.add_proxy_content(mock_proxy, 0)

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

        manager = McpProxyManager(mock_target_mcp, False)
        # Should not raise an exception
        await manager.add_proxy_content(mock_proxy, 0)

        # Verify tools were still added
        mock_target_mcp.add_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_tools_no_annotations(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools with no annotations are skipped when read_only=True."""
        # Setup tool with no annotations
        mock_tool.annotations = None

        mock_proxy.get_tools.return_value = {'no_annotations_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, read_only=True)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_tools_empty_annotations(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that tools with empty annotations are skipped when read_only=True."""
        # Setup tool with empty annotations
        mock_tool.annotations = {}

        mock_proxy.get_tools.return_value = {'empty_annotations_tool': mock_tool}

        manager = McpProxyManager(mock_target_mcp, read_only=True)
        await manager._add_tools(mock_proxy)

        # Verify tool was not added (skipped)
        mock_target_mcp.add_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_retry_middleware_to_proxy(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that retry middleware is added to proxy during add_proxy_content."""
        # Setup proxy
        mock_proxy.add_middleware = MagicMock()
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.return_value = {}
        mock_proxy.get_prompts.return_value = {}

        manager = McpProxyManager(mock_target_mcp, False)
        await manager.add_proxy_content(mock_proxy, 1)

        # Verify retry middleware was added to proxy
        mock_proxy.add_middleware.assert_called_once()

        # Check that RetryMiddleware was added
        retry_call = mock_proxy.add_middleware.call_args_list[0]
        retry_middleware = retry_call[0][0]
        assert isinstance(retry_middleware, RetryMiddleware)

    @pytest.mark.asyncio
    async def test_disable_retry_middleware_to_proxy(self, mock_target_mcp, mock_proxy, mock_tool):
        """Test that retry middleware is added to proxy during add_proxy_content."""
        # Setup proxy
        mock_proxy.add_middleware = MagicMock()
        mock_proxy.get_tools.return_value = {'test_tool': mock_tool}
        mock_proxy.get_resources.return_value = {}
        mock_proxy.get_prompts.return_value = {}

        manager = McpProxyManager(mock_target_mcp, False)
        await manager.add_proxy_content(mock_proxy, 0)

        # Verify retry middleware was added to proxy
        mock_proxy.add_middleware.assert_not_called()

    def test_add_retry_middleware_configuration(self, mock_target_mcp):
        """Test that RetryMiddleware is configured correctly."""
        proxy = MagicMock()
        proxy.add_middleware = MagicMock()

        manager = McpProxyManager(mock_target_mcp, False)
        manager._add_retry_middleware(proxy, 1)

        # Get the RetryMiddleware instance that was added
        retry_call = proxy.add_middleware.call_args_list[0]
        retry_middleware = retry_call[0][0]

        # Verify it's the correct type
        assert isinstance(retry_middleware, RetryMiddleware)


class TestRetryBehavior:
    """Functional tests for retry behavior through McpProxyManager."""

    @pytest.mark.asyncio
    async def test_proxy_manager_adds_retry_middleware(self):
        """Test that McpProxyManager adds retry middleware to proxy servers."""
        from fastmcp.server.server import FastMCP

        # Create target server and proxy manager
        target_server = FastMCP('target-server')
        manager = McpProxyManager(target_server, False)

        # Create a simple proxy server
        proxy_server = FastMCP('proxy-server')

        # Add proxy content - this should add retry middleware to the proxy
        await manager.add_proxy_content(proxy_server, 1)

        # Verify retry middleware was added to the proxy
        retry_middleware_found = False
        retry_middleware = None
        for middleware in proxy_server.middleware:
            if isinstance(middleware, RetryMiddleware):
                retry_middleware = middleware

                retry_middleware_found = True
                break

        assert retry_middleware_found, 'Retry middleware not found on proxy server'
        # Verify it has the expected default configuration
        assert hasattr(retry_middleware, 'max_retries')
        assert hasattr(retry_middleware, 'base_delay')
        assert hasattr(retry_middleware, 'backoff_multiplier')
        assert hasattr(retry_middleware, 'retry_exceptions')

    @pytest.mark.asyncio
    async def test_retry_middleware_handles_failures_through_middleware(self):
        """Test that retry middleware handles failures correctly."""
        from fastmcp.server.middleware.middleware import MiddlewareContext
        from fastmcp.server.server import FastMCP

        target_server = FastMCP('target-server')
        manager = McpProxyManager(target_server, False)

        # Create a simple proxy server
        proxy_server = FastMCP('proxy-server')

        # Add proxy content to get retry middleware added
        await manager.add_proxy_content(proxy_server, 3)

        # Get the retry middleware
        retry_middleware = None
        for middleware in proxy_server.middleware:
            if isinstance(middleware, RetryMiddleware):
                retry_middleware = middleware
                break

        assert retry_middleware is not None, 'Retry middleware not found'

        # Test retry behavior by calling the middleware directly with proper context
        mock_request = MagicMock()
        mock_request.method = 'tools/call'

        context = MiddlewareContext(message=mock_request, type='request', method='tools/call')

        call_count = 0

        async def failing_then_success(context):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # Fail first 2 attempts
                raise ConnectionError(f'Connection failed attempt {call_count}')
            return 'success'

        # Test retry through the middleware added by McpProxyManager
        result = await retry_middleware.on_request(context, failing_then_success)

        assert result == 'success'
        assert call_count == 3, f'Expected 3 calls (2 failures + 1 success), got {call_count}'

    @pytest.mark.asyncio
    async def test_retry_middleware_handles_different_exceptions(self):
        """Test that retry middleware handles different types of retriable exceptions."""
        from fastmcp.server.middleware.middleware import MiddlewareContext
        from fastmcp.server.server import FastMCP

        target_server = FastMCP('target-server')
        manager = McpProxyManager(target_server, False)

        # Create a simple proxy server
        proxy_server = FastMCP('proxy-server')

        # Add proxy content to get retry middleware added
        await manager.add_proxy_content(proxy_server, 1)

        # Get the retry middleware
        retry_middleware = None
        for middleware in proxy_server.middleware:
            if isinstance(middleware, RetryMiddleware):
                retry_middleware = middleware
                break

        # Test with TimeoutError
        mock_request = MagicMock()
        context = MiddlewareContext(message=mock_request, type='request', method='tools/call')

        call_count = 0

        async def timeout_then_success(context):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise TimeoutError('Request timed out')
            return 'success after timeout'

        assert retry_middleware is not None, 'RetryMiddleware should be found'

        result = await retry_middleware.on_request(context, timeout_then_success)

        assert result == 'success after timeout'
        assert call_count == 2, f'Expected 2 calls (1 timeout + 1 success), got {call_count}'

    @pytest.mark.asyncio
    async def test_successful_requests_pass_through(self):
        """Test that successful requests pass through without retry."""
        from fastmcp.server.middleware.middleware import MiddlewareContext
        from fastmcp.server.server import FastMCP

        target_server = FastMCP('target-server')
        manager = McpProxyManager(target_server, False)

        # Create a simple proxy server
        proxy_server = FastMCP('proxy-server')

        # Add proxy content to get retry middleware added
        await manager.add_proxy_content(proxy_server, 1)

        # Get the retry middleware
        retry_middleware = None
        for middleware in proxy_server.middleware:
            if isinstance(middleware, RetryMiddleware):
                retry_middleware = middleware
                break

        mock_request = MagicMock()
        context = MiddlewareContext(message=mock_request, type='request', method='tools/call')

        call_count = 0

        async def successful_call(context):
            nonlocal call_count
            call_count += 1
            return 'success'

        assert retry_middleware is not None, 'RetryMiddleware should be found'

        result = await retry_middleware.on_request(context, successful_call)

        assert result == 'success'
        assert call_count == 1, f'Expected 1 call (no retries needed), got {call_count}'

    @pytest.mark.asyncio
    async def test_retry_does_not_retry_non_retriable_exceptions(self):
        """Test that non-retriable exceptions are not retried."""
        from fastmcp.server.middleware.middleware import MiddlewareContext
        from fastmcp.server.server import FastMCP

        target_server = FastMCP('target-server')
        manager = McpProxyManager(target_server, False)

        # Create a simple proxy server
        proxy_server = FastMCP('proxy-server')

        # Add proxy content to get retry middleware added
        await manager.add_proxy_content(proxy_server, 1)

        # Get the retry middleware
        retry_middleware = None
        for middleware in proxy_server.middleware:
            if isinstance(middleware, RetryMiddleware):
                retry_middleware = middleware
                break

        mock_request = MagicMock()
        context = MiddlewareContext(message=mock_request, type='request', method='tools/call')

        call_count = 0

        async def value_error_call(context):
            nonlocal call_count
            call_count += 1
            raise ValueError('This should not be retried')

        # Should raise immediately without retries (if ValueError is not in retry_exceptions)
        with pytest.raises(ValueError, match='This should not be retried'):
            assert retry_middleware is not None, 'RetryMiddleware should be found'

            await retry_middleware.on_request(context, value_error_call)

        # Should have been called only once (no retries for non-retriable exceptions)
        assert call_count == 1, f'Expected 1 call (no retries), got {call_count}'
