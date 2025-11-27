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

"""Tests for _initialize_client error handling."""

import httpx
import pytest
from mcp import McpError
from mcp.types import ErrorData, JSONRPCError, JSONRPCResponse
from mcp_proxy_for_aws.server import _initialize_client
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
async def test_successful_initialization():
    """Test successful client initialization."""
    mock_transport = Mock()
    mock_client = Mock()

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        async with _initialize_client(mock_transport) as client:
            assert client == mock_client


@pytest.mark.asyncio
async def test_http_error_with_jsonrpc_error(capsys):
    """Test HTTPStatusError with JSONRPCError response."""
    mock_transport = Mock()
    error_data = ErrorData(code=-32600, message='Invalid Request')
    jsonrpc_error = JSONRPCError(jsonrpc='2.0', id=1, error=error_data)

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=jsonrpc_error.model_dump_json().encode())

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=http_error)

        with pytest.raises(httpx.HTTPStatusError):
            async with _initialize_client(mock_transport):
                pass

        captured = capsys.readouterr()
        assert 'Invalid Request' in captured.out


@pytest.mark.asyncio
async def test_http_error_with_jsonrpc_response(capsys):
    """Test HTTPStatusError with JSONRPCResponse."""
    mock_transport = Mock()
    jsonrpc_response = JSONRPCResponse(jsonrpc='2.0', id=1, result={'status': 'error'})

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=jsonrpc_response.model_dump_json().encode())

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=http_error)

        with pytest.raises(httpx.HTTPStatusError):
            async with _initialize_client(mock_transport):
                pass

        captured = capsys.readouterr()
        assert '"result":{"status":"error"}' in captured.out


@pytest.mark.asyncio
async def test_http_error_with_invalid_json():
    """Test HTTPStatusError with invalid JSON response."""
    mock_transport = Mock()

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=b'invalid json')

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=http_error)

        with pytest.raises(httpx.HTTPStatusError):
            async with _initialize_client(mock_transport):
                pass


@pytest.mark.asyncio
async def test_http_error_with_non_jsonrpc_message():
    """Test HTTPStatusError with non-JSONRPCError/Response message."""
    mock_transport = Mock()

    mock_response = Mock()
    mock_response.aread = AsyncMock(return_value=b'{"jsonrpc":"2.0","method":"test"}')

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=http_error)

        with pytest.raises(httpx.HTTPStatusError):
            async with _initialize_client(mock_transport):
                pass


@pytest.mark.asyncio
async def test_http_error_response_read_failure():
    """Test HTTPStatusError when response.aread() fails."""
    mock_transport = Mock()

    mock_response = Mock()
    mock_response.aread = AsyncMock(side_effect=Exception('Read failed'))

    http_error = httpx.HTTPStatusError('error', request=Mock(), response=mock_response)

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=http_error)

        with pytest.raises(httpx.HTTPStatusError):
            async with _initialize_client(mock_transport):
                pass


@pytest.mark.asyncio
async def test_generic_error_with_mcp_error_cause(capsys):
    """Test generic exception with McpError as cause."""
    mock_transport = Mock()
    error_data = ErrorData(code=-32601, message='Method not found')
    mcp_error = McpError(error_data)
    generic_error = Exception('Wrapper error')
    generic_error.__cause__ = mcp_error

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=generic_error)

        with pytest.raises(Exception):
            async with _initialize_client(mock_transport):
                pass

        captured = capsys.readouterr()
        assert 'Method not found' in captured.out
        assert '"code":-32601' in captured.out


@pytest.mark.asyncio
async def test_generic_error_without_mcp_error_cause(capsys):
    """Test generic exception without McpError cause."""
    mock_transport = Mock()
    generic_error = Exception('Generic error')

    with patch('mcp_proxy_for_aws.server.ProxyClient') as mock_client_class:
        mock_client_class.return_value.__aenter__ = AsyncMock(side_effect=generic_error)

        with pytest.raises(Exception):
            async with _initialize_client(mock_transport):
                pass

        captured = capsys.readouterr()
        assert 'Generic error' in captured.out
        assert '"code":-32000' in captured.out
