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

import pytest
from fastmcp.server.middleware import MiddlewareContext
from mcp_proxy_for_aws.middleware.empty_tools_retry import EmptyToolsRetryMiddleware
from unittest.mock import AsyncMock, Mock


@pytest.fixture
def mock_context():
    """Mock MiddlewareContext."""
    return Mock(spec=MiddlewareContext)


@pytest.fixture
def tool():
    """Mock tool."""
    tool = Mock()
    tool.name = 'test_tool'
    return tool


@pytest.mark.asyncio
async def test_returns_tools_without_retry(mock_context, tool):
    """Test that a non-empty tool list is returned without retry."""
    call_next_mock = AsyncMock(return_value=[tool])
    middleware = EmptyToolsRetryMiddleware(retries=2, backoff_seconds=0)

    result = await middleware.on_list_tools(mock_context, call_next_mock)

    assert result == [tool]
    call_next_mock.assert_called_once_with(mock_context)


@pytest.mark.asyncio
async def test_retries_empty_tools_until_non_empty(mock_context, tool):
    """Test that empty tools/list responses are retried."""
    call_next_mock = AsyncMock(side_effect=[[], [], [tool]])
    middleware = EmptyToolsRetryMiddleware(retries=2, backoff_seconds=0)

    result = await middleware.on_list_tools(mock_context, call_next_mock)

    assert result == [tool]
    assert call_next_mock.call_count == 3


@pytest.mark.asyncio
async def test_returns_empty_after_retries_exhausted(mock_context):
    """Test that empty tools/list is returned after retries are exhausted."""
    call_next_mock = AsyncMock(return_value=[])
    middleware = EmptyToolsRetryMiddleware(retries=2, backoff_seconds=0)

    result = await middleware.on_list_tools(mock_context, call_next_mock)

    assert result == []
    assert call_next_mock.call_count == 3


@pytest.mark.asyncio
async def test_zero_retries_preserves_empty_tools_response(mock_context):
    """Test that retries=0 preserves an empty tools/list response."""
    call_next_mock = AsyncMock(return_value=[])
    middleware = EmptyToolsRetryMiddleware(retries=0, backoff_seconds=0)

    result = await middleware.on_list_tools(mock_context, call_next_mock)

    assert result == []
    call_next_mock.assert_called_once_with(mock_context)
