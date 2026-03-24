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

import mcp.types as mt
import pytest
from mcp import McpError
from mcp.shared.session import RequestResponder
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
async def test_patched_received_request_initialize_success():
    """Test that patched _received_request calls original for successful initialize."""
    # Import after patching is applied
    import fastmcp.server.low_level as low_level_module
    from mcp_proxy_for_aws import fastmcp_patch

    mock_self = Mock()
    mock_self.fastmcp = Mock()

    mock_request = Mock()
    mock_request.root = Mock(spec=mt.InitializeRequest)

    mock_responder = Mock(spec=RequestResponder)
    mock_responder.request = mock_request

    with patch.object(
        fastmcp_patch, 'original_receive_request', new_callable=AsyncMock
    ) as mock_original:
        await low_level_module.MiddlewareServerSession._received_request(mock_self, mock_responder)
        mock_original.assert_called_once_with(mock_self, mock_responder)


@pytest.mark.asyncio
async def test_patched_received_request_initialize_mcp_error_not_completed():
    """Test that patched _received_request handles McpError when responder not completed."""
    import fastmcp.server.low_level as low_level_module
    from mcp_proxy_for_aws import fastmcp_patch

    mock_self = Mock()
    mock_self.fastmcp = Mock()

    mock_request = Mock()
    mock_request.root = Mock(spec=mt.InitializeRequest)

    mock_responder = Mock(spec=RequestResponder)
    mock_responder.request = mock_request
    mock_responder._completed = False
    mock_responder.__enter__ = Mock(return_value=mock_responder)
    mock_responder.__exit__ = Mock(return_value=False)
    mock_responder.respond = AsyncMock()

    error = mt.ErrorData(code=1, message='test error')
    mcp_error = McpError(error=error)

    with patch.object(
        fastmcp_patch, 'original_receive_request', new_callable=AsyncMock, side_effect=mcp_error
    ):
        await low_level_module.MiddlewareServerSession._received_request(mock_self, mock_responder)
        mock_responder.respond.assert_called_once_with(error)


@pytest.mark.asyncio
async def test_patched_received_request_initialize_mcp_error_completed():
    """Test that patched _received_request re-raises McpError when responder completed."""
    import fastmcp.server.low_level as low_level_module
    from mcp_proxy_for_aws import fastmcp_patch

    mock_self = Mock()
    mock_self.fastmcp = Mock()

    mock_request = Mock()
    mock_request.root = Mock(spec=mt.InitializeRequest)

    mock_responder = Mock(spec=RequestResponder)
    mock_responder.request = mock_request
    mock_responder._completed = True

    error = mt.ErrorData(code=1, message='test error')
    mcp_error = McpError(error=error)

    with patch.object(
        fastmcp_patch, 'original_receive_request', new_callable=AsyncMock, side_effect=mcp_error
    ):
        with pytest.raises(McpError):
            await low_level_module.MiddlewareServerSession._received_request(
                mock_self, mock_responder
            )


@pytest.mark.asyncio
async def test_patched_received_request_non_initialize():
    """Test that patched _received_request calls original for non-initialize requests."""
    import fastmcp.server.low_level as low_level_module
    from mcp_proxy_for_aws import fastmcp_patch

    mock_self = Mock()

    mock_request = Mock()
    mock_request.root = Mock(spec=mt.CallToolRequest)

    mock_responder = Mock(spec=RequestResponder)
    mock_responder.request = mock_request

    with patch.object(
        fastmcp_patch, 'original_receive_request', new_callable=AsyncMock
    ) as mock_original:
        await low_level_module.MiddlewareServerSession._received_request(mock_self, mock_responder)
        mock_original.assert_called_once_with(mock_self, mock_responder)
