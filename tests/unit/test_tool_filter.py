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

"""Tests for the tool filtering middleware."""

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from mcp_proxy_for_aws.middleware.tool_filter import ToolFilteringMiddleware
from unittest.mock import AsyncMock, Mock


class MockAnnotationsWithoutReadOnlyHint:
    """Mock annotations object that raises AttributeError for readOnlyHint."""

    def __getattr__(self, name):
        """Mocks get attribute behavior when accessing readOnlyHint by raising an Error."""
        if name == 'readOnlyHint':
            raise AttributeError(f"'{type(self).__name__}' object has no attribute 'readOnlyHint'")
        return Mock()


class TestToolFilteringMiddleware:
    """Tests for the ToolFilteringMiddleware class."""

    def test_constructor_read_only_false(self):
        """Test constructor with read_only=False."""
        # Arrange & Act
        middleware = ToolFilteringMiddleware(read_only=False)

        # Assert
        assert middleware.read_only is False
        assert middleware.logger is not None

    def test_constructor_read_only_true(self):
        """Test constructor with read_only=True."""
        # Arrange & Act
        middleware = ToolFilteringMiddleware(read_only=True)

        # Assert
        assert middleware.read_only is True
        assert middleware.logger is not None


class TestOnListTools:
    """Tests for the on_list_tools method."""

    @pytest.fixture
    def mock_context(self):
        """Mock MiddlewareContext."""
        return Mock(spec=MiddlewareContext)

    @pytest.fixture
    def read_only_tool(self):
        """Tool with readOnlyHint=True."""
        tool = Mock()
        tool.name = 'read_only_tool'
        tool.annotations = Mock()
        tool.annotations.readOnlyHint = True
        return tool

    @pytest.fixture
    def write_tool(self):
        """Tool with readOnlyHint=False."""
        tool = Mock()
        tool.name = 'write_tool'
        tool.annotations = Mock()
        tool.annotations.readOnlyHint = False
        return tool

    @pytest.fixture
    def no_hint_tool(self):
        """Tool with annotations but no readOnlyHint."""
        tool = Mock()
        tool.name = 'no_hint_tool'
        tool.annotations = MockAnnotationsWithoutReadOnlyHint()
        return tool

    @pytest.fixture
    def no_annotations_tool(self):
        """Tool with no annotations."""
        tool = Mock()
        tool.name = 'no_annotations_tool'
        tool.annotations = None
        return tool

    @pytest.mark.asyncio
    async def test_read_only_false_returns_all_tools(
        self, mock_context, read_only_tool, write_tool, no_annotations_tool
    ):
        """Test that read_only=False returns all tools unchanged."""
        # Arrange
        tools = [read_only_tool, write_tool, no_annotations_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=False)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert result == tools
        assert len(result) == 3
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_filters_write_tools(
        self, mock_context, read_only_tool, write_tool
    ):
        """Test that read_only=True filters out write tools."""
        # Arrange
        tools = [read_only_tool, write_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert len(result) == 1
        assert result[0] == read_only_tool
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_filters_no_annotations_tools(
        self, mock_context, read_only_tool, no_annotations_tool
    ):
        """Test that read_only=True filters out tools with no annotations."""
        # Arrange
        tools = [read_only_tool, no_annotations_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert len(result) == 1
        assert result[0] == read_only_tool
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_filters_no_hint_tools(
        self, mock_context, read_only_tool, no_hint_tool
    ):
        """Test that read_only=True filters out tools without readOnlyHint."""
        # Arrange
        tools = [read_only_tool, no_hint_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert len(result) == 1
        assert result[0] == read_only_tool
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_with_empty_tool_list(self, mock_context):
        """Test that read_only=True handles empty tool list."""
        # Arrange
        tools = []
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert result == []
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_with_only_read_only_tools(self, mock_context, read_only_tool):
        """Test that read_only=True passes through read-only tools."""
        # Arrange
        read_only_tool2 = Mock()
        read_only_tool2.name = 'read_only_tool2'
        read_only_tool2.annotations = Mock()
        read_only_tool2.annotations.readOnlyHint = True

        tools = [read_only_tool, read_only_tool2]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert len(result) == 2
        assert result == tools
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_read_only_true_with_only_write_tools(
        self, mock_context, write_tool, no_annotations_tool
    ):
        """Test that read_only=True filters all write tools."""
        # Arrange
        tools = [write_tool, no_annotations_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert result == []
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_call_next_exception_propagated(self, mock_context):
        """Test that exceptions from call_next are propagated."""
        # Arrange
        call_next_mock = AsyncMock(side_effect=Exception('call_next failed'))
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await middleware.on_list_tools(mock_context, call_next_mock)

        assert 'call_next failed' in str(exc_info.value)
        call_next_mock.assert_called_once_with(mock_context)

    @pytest.mark.parametrize(
        'read_only,expected_count',
        [
            (False, 4),  # All tools pass through
            (True, 1),  # Only read-only tools pass
        ],
    )
    @pytest.mark.asyncio
    async def test_parametrized_filtering_behavior(
        self,
        mock_context,
        read_only_tool,
        write_tool,
        no_annotations_tool,
        no_hint_tool,
        read_only,
        expected_count,
    ):
        """Test filtering behavior with different read_only settings."""
        # Arrange
        tools = [read_only_tool, write_tool, no_annotations_tool, no_hint_tool]
        call_next_mock = AsyncMock(return_value=tools)
        middleware = ToolFilteringMiddleware(read_only=read_only)

        # Act
        result = await middleware.on_list_tools(mock_context, call_next_mock)

        # Assert
        assert len(result) == expected_count
        if read_only:
            # Only the read_only_tool should pass
            assert result == [read_only_tool]
        else:
            # All tools should pass
            assert result == tools


class TestOnCallTool:
    """Tests for the on_call_tool method."""

    @pytest.fixture
    def mock_read_only_tool(self):
        """Tool with readOnlyHint=True."""
        tool = Mock()
        tool.name = 'read_only_tool'
        tool.annotations = Mock()
        tool.annotations.readOnlyHint = True
        return tool

    @pytest.fixture
    def mock_write_tool(self):
        """Tool with readOnlyHint=False."""
        tool = Mock()
        tool.name = 'write_tool'
        tool.annotations = Mock()
        tool.annotations.readOnlyHint = False
        return tool

    def _make_context(self, tool_name, get_tool_return):
        """Create a mock MiddlewareContext for on_call_tool."""
        context = Mock(spec=MiddlewareContext)
        context.message = Mock()
        context.message.name = tool_name
        context.fastmcp_context = Mock()
        context.fastmcp_context.fastmcp = Mock()
        context.fastmcp_context.fastmcp.get_tool = AsyncMock(return_value=get_tool_return)
        return context

    @pytest.mark.asyncio
    async def test_read_only_false_allows_all_calls(self, mock_write_tool):
        """Test that read_only=False passes through all tool calls."""
        # Arrange
        context = self._make_context('write_tool', mock_write_tool)
        call_next = AsyncMock(return_value=['result'])
        middleware = ToolFilteringMiddleware(read_only=False)

        # Act
        result = await middleware.on_call_tool(context, call_next)

        # Assert
        assert result == ['result']
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_read_only_true_allows_read_only_tool(self, mock_read_only_tool):
        """Test that read_only=True allows tools with readOnlyHint=True."""
        # Arrange
        context = self._make_context('read_only_tool', mock_read_only_tool)
        call_next = AsyncMock(return_value=['result'])
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_call_tool(context, call_next)

        # Assert
        assert result == ['result']
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_read_only_true_rejects_write_tool(self, mock_write_tool):
        """Test that read_only=True rejects tools with readOnlyHint=False."""
        # Arrange
        context = self._make_context('write_tool', mock_write_tool)
        call_next = AsyncMock()
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act & Assert
        with pytest.raises(ToolError) as exc_info:
            await middleware.on_call_tool(context, call_next)

        assert 'write_tool' in str(exc_info.value)
        assert 'not available in read-only mode' in str(exc_info.value)
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_only_true_rejects_unknown_tool(self):
        """Test that read_only=True rejects tools that don't exist."""
        # Arrange
        context = self._make_context('unknown_tool', None)
        call_next = AsyncMock()
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act & Assert
        with pytest.raises(ToolError) as exc_info:
            await middleware.on_call_tool(context, call_next)

        assert 'unknown_tool' in str(exc_info.value)
        assert 'not available in read-only mode' in str(exc_info.value)
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_only_true_rejects_tool_without_annotations(self):
        """Test that read_only=True rejects tools with no annotations."""
        # Arrange
        tool = Mock()
        tool.name = 'no_annotations_tool'
        tool.annotations = None
        context = self._make_context('no_annotations_tool', tool)
        call_next = AsyncMock()
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act & Assert
        with pytest.raises(ToolError) as exc_info:
            await middleware.on_call_tool(context, call_next)

        assert 'no_annotations_tool' in str(exc_info.value)
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_only_true_no_fastmcp_context_passes_through(self):
        """Test that when fastmcp_context is None, call passes through."""
        # Arrange
        context = Mock(spec=MiddlewareContext)
        context.message = Mock()
        context.message.name = 'some_tool'
        context.fastmcp_context = None
        call_next = AsyncMock(return_value=['result'])
        middleware = ToolFilteringMiddleware(read_only=True)

        # Act
        result = await middleware.on_call_tool(context, call_next)

        # Assert
        assert result == ['result']
        call_next.assert_called_once_with(context)
