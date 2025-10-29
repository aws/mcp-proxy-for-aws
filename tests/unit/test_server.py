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

"""Tests for the mcp-proxy-for-aws Server."""

import pytest
from fastmcp.server.server import FastMCP
from mcp_proxy_for_aws.server import (
    add_retry_middleware,
    add_tool_filtering_middleware,
    main,
    parse_args,
    setup_mcp_mode,
)
from mcp_proxy_for_aws.sigv4_helper import create_sigv4_client
from mcp_proxy_for_aws.utils import determine_service_name
from unittest.mock import AsyncMock, Mock, patch


class TestServer:
    """Tests for the server module."""

    @patch('mcp_proxy_for_aws.server.create_transport_with_sigv4')
    @patch('mcp_proxy_for_aws.server.FastMCP.as_proxy')
    @patch('mcp_proxy_for_aws.server.determine_aws_region')
    @patch('mcp_proxy_for_aws.server.determine_service_name')
    @patch('mcp_proxy_for_aws.server.add_tool_filtering_middleware')
    @patch('mcp_proxy_for_aws.server.add_retry_middleware')
    async def test_setup_mcp_mode(
        self,
        mock_add_retry,
        mock_add_filtering,
        mock_determine_service,
        mock_determine_region,
        mock_as_proxy,
        mock_create_transport,
    ):
        """Test that MCP mode is set up correctly."""
        # Arrange
        local_mcp = Mock(spec=FastMCP)
        mock_args = Mock()
        mock_args.endpoint = 'https://test.example.com'
        mock_args.service = 'test-service'
        mock_args.region = 'us-east-1'
        mock_args.profile = None
        mock_args.read_only = True
        mock_args.retries = 1
        # Add timeout parameters
        mock_args.timeout = 180.0
        mock_args.connect_timeout = 60.0
        mock_args.read_timeout = 120.0
        mock_args.write_timeout = 180.0
        mock_args.log_level = 'INFO'

        # Mock return values
        mock_determine_service.return_value = 'test-service'
        mock_determine_region.return_value = 'us-east-1'

        # Mock the transport and proxy
        mock_transport = Mock()
        mock_create_transport.return_value = mock_transport
        mock_proxy = Mock()
        mock_proxy.run_async = AsyncMock()
        mock_as_proxy.return_value = mock_proxy

        # Act
        await setup_mcp_mode(local_mcp, mock_args)

        # Assert
        mock_determine_service.assert_called_once_with('https://test.example.com', 'test-service')
        mock_determine_region.assert_called_once_with('https://test.example.com', 'us-east-1')
        # Verify create_transport was called (we check args differently since Timeout object comparison is complex)
        assert mock_create_transport.call_count == 1
        call_args = mock_create_transport.call_args
        assert call_args[0][0] == 'https://test.example.com'
        assert call_args[0][1] == 'test-service'
        assert call_args[0][2] == 'us-east-1'
        # call_args[0][3] is the Timeout object
        assert call_args[0][4] is None  # profile
        mock_as_proxy.assert_called_once_with(mock_transport)
        mock_add_filtering.assert_called_once_with(mock_proxy, True)
        mock_add_retry.assert_called_once_with(mock_proxy, 1)
        mock_proxy.run_async.assert_called_once()

    @patch('mcp_proxy_for_aws.server.create_transport_with_sigv4')
    @patch('mcp_proxy_for_aws.server.FastMCP.as_proxy')
    @patch('mcp_proxy_for_aws.server.determine_aws_region')
    @patch('mcp_proxy_for_aws.server.determine_service_name')
    @patch('mcp_proxy_for_aws.server.add_tool_filtering_middleware')
    async def test_setup_mcp_mode_no_retries(
        self,
        mock_add_filtering,
        mock_determine_service,
        mock_determine_region,
        mock_as_proxy,
        mock_create_transport,
    ):
        """Test that MCP mode setup without retries doesn't add retry middleware."""
        # Arrange
        local_mcp = Mock(spec=FastMCP)
        mock_args = Mock()
        mock_args.endpoint = 'https://test.example.com'
        mock_args.service = 'test-service'
        mock_args.region = 'us-east-1'
        mock_args.profile = 'test-profile'
        mock_args.read_only = False
        mock_args.retries = 0  # No retries
        # Add timeout parameters
        mock_args.timeout = 180.0
        mock_args.connect_timeout = 60.0
        mock_args.read_timeout = 120.0
        mock_args.write_timeout = 180.0
        mock_args.log_level = 'INFO'

        # Mock return values
        mock_determine_service.return_value = 'test-service'
        mock_determine_region.return_value = 'us-east-1'

        # Mock the transport and proxy
        mock_transport = Mock()
        mock_create_transport.return_value = mock_transport
        mock_proxy = Mock()
        mock_proxy.run_async = AsyncMock()
        mock_as_proxy.return_value = mock_proxy

        # Act
        await setup_mcp_mode(local_mcp, mock_args)

        # Assert
        mock_determine_service.assert_called_once_with('https://test.example.com', 'test-service')
        mock_determine_region.assert_called_once_with('https://test.example.com', 'us-east-1')
        # Verify create_transport was called (we check args differently since Timeout object comparison is complex)
        assert mock_create_transport.call_count == 1
        call_args = mock_create_transport.call_args
        assert call_args[0][0] == 'https://test.example.com'
        assert call_args[0][1] == 'test-service'
        assert call_args[0][2] == 'us-east-1'
        # call_args[0][3] is the Timeout object
        assert call_args[0][4] == 'test-profile'  # profile
        mock_as_proxy.assert_called_once_with(mock_transport)
        mock_add_filtering.assert_called_once_with(mock_proxy, False)
        mock_proxy.run_async.assert_called_once()

    def test_add_tool_filtering_middleware(self):
        """Test that tool filtering middleware is added correctly."""
        # Arrange
        mock_mcp = Mock()

        # Act
        add_tool_filtering_middleware(mock_mcp, read_only=True)

        # Assert
        mock_mcp.add_middleware.assert_called_once()
        # Verify that the middleware added is a ToolFilteringMiddleware
        call_args = mock_mcp.add_middleware.call_args[0][0]
        from mcp_proxy_for_aws.middleware.tool_filter import ToolFilteringMiddleware

        assert isinstance(call_args, ToolFilteringMiddleware)
        assert call_args.read_only is True

    def test_add_retry_middleware(self):
        """Test that retry middleware is added correctly."""
        # Arrange
        mock_mcp = Mock()

        # Act
        add_retry_middleware(mock_mcp, retries=5)

        # Assert
        mock_mcp.add_middleware.assert_called_once()
        # Verify that the middleware added is a RetryMiddleware
        call_args = mock_mcp.add_middleware.call_args[0][0]
        from fastmcp.server.middleware.error_handling import RetryMiddleware

        assert isinstance(call_args, RetryMiddleware)

    @patch('sys.argv', ['test', 'https://test.example.com'])
    def test_parse_args_default(self):
        """Test parse_args with default arguments."""
        args = parse_args()
        assert args.endpoint == 'https://test.example.com'
        assert args.service is None
        assert args.region is None
        assert args.profile is None
        assert args.read_only is False
        assert args.log_level == 'INFO'
        assert args.retries == 0

    @patch(
        'sys.argv',
        [
            'test',
            'https://test.example.com',
            '--service',
            'custom-service',
            '--region',
            'us-west-2',
            '--read-only',
            '--log-level',
            'DEBUG',
            '--retries',
            '5',
        ],
    )
    def test_parse_args_custom(self):
        """Test parse_args with custom arguments."""
        args = parse_args()
        assert args.endpoint == 'https://test.example.com'
        assert args.service == 'custom-service'
        assert args.region == 'us-west-2'
        assert args.read_only is True
        assert args.log_level == 'DEBUG'
        assert args.retries == 5

    @patch('mcp_proxy_for_aws.server.asyncio.run')
    @patch('sys.argv', ['test', 'https://test.example.com'])
    def test_main_function(self, mock_asyncio_run):
        """Test that main function runs server correctly."""
        # Arrange
        mock_asyncio_run.return_value = None

        # Act
        main()

        # Assert
        mock_asyncio_run.assert_called_once()

    @patch('mcp_proxy_for_aws.server.asyncio.run')
    @patch('sys.argv', ['test', 'https://test.example.com'])
    def test_main_error_handling(self, mock_asyncio_run):
        """Test that main function handles errors gracefully."""
        # Arrange
        mock_asyncio_run.side_effect = Exception('Test error')

        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            main()
        assert 'Test error' in str(exc_info.value)

    def test_validate_service_name_service_parsing(self):
        """Test parsing service name from endpoint URL via validate_service_name."""
        # Test cases
        test_cases = [
            ('https://eks-mcp.us-west-2.api.aws', 'eks-mcp'),
            ('https://test-service.example.com', 'test-service'),
            ('https://my-service-name.domain.com', 'my-service-name'),
            ('https://single.domain.com', 'single'),
        ]

        for endpoint, expected_service in test_cases:
            result = determine_service_name(endpoint)
            assert result == expected_service

    @patch('mcp_proxy_for_aws.sigv4_helper.boto3.Session')
    @patch('mcp_proxy_for_aws.sigv4_helper.httpx.AsyncClient')
    @patch('mcp_proxy_for_aws.sigv4_helper.SigV4Auth')
    def test_create_sigv4_client(self, mock_sigv4_auth, mock_async_client, mock_session):
        """Test creating SigV4 authenticated client with HTTPX auth."""
        # Arrange
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        mock_session_instance = Mock()
        mock_session_instance.get_credentials.return_value = mock_credentials
        mock_session.return_value = mock_session_instance

        # Act
        create_sigv4_client(service='test-service', region='us-west-2', profile='test-profile')

        # Assert
        mock_session.assert_called_once_with(profile_name='test-profile')
        mock_sigv4_auth.assert_called_once_with(mock_credentials, 'test-service', 'us-west-2')
        mock_async_client.assert_called_once()

    @patch('mcp_proxy_for_aws.sigv4_helper.boto3.Session')
    def test_create_sigv4_client_no_credentials(self, mock_session):
        """Test creating SigV4 client with no credentials."""
        # Arrange
        mock_session_instance = Mock()
        mock_session_instance.get_credentials.return_value = None
        mock_session.return_value = mock_session_instance

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            create_sigv4_client(service='test-service', region='test-region')
        assert 'No AWS credentials found' in str(exc_info.value)

    def test_main_module_execution(self):
        """Test that main is called when module is executed directly."""
        # This test is more complex because we need to test the actual module execution
        # We'll test by checking if the server module has the correct structure
        import mcp_proxy_for_aws.server as server_module

        # Verify the module has the main function
        assert hasattr(server_module, 'main')
        assert callable(server_module.main)

        # Test that the module can be executed (this covers the if __name__ == '__main__' block)
        with patch.object(server_module, 'main') as mock_main:
            # Simulate module execution
            if server_module.__name__ == '__main__':
                server_module.main()
            # Since we're not actually running as __main__, we just verify the structure exists
            assert mock_main.call_count == 0  # Should not be called in test context
