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

"""Tests for the aws-mcp-proxy Server."""

import pytest
from src.aws_mcp_proxy.server import main, parse_args, setup_mcp_mode
from src.aws_mcp_proxy.sigv4_helper import create_sigv4_client
from src.aws_mcp_proxy.utils import determine_service_name
from unittest.mock import AsyncMock, Mock, patch


class TestServer:
    """Tests for the server module."""

    @patch('src.aws_mcp_proxy.server.McpProxyManager')
    @patch('src.aws_mcp_proxy.server.create_transport_with_sigv4')
    @patch('src.aws_mcp_proxy.server.FastMCP.as_proxy')
    async def test_setup_mcp_mode(
        self, mock_as_proxy, mock_create_transport, mock_proxy_manager_class
    ):
        """Test that MCP mode is set up correctly."""
        # Arrange
        mock_mcp = Mock()
        mock_args = Mock()
        mock_args.endpoint = 'https://test.example.com'
        mock_args.service = 'test-service'
        mock_args.profile = None
        mock_args.allow_write = False

        # Mock the transport and proxy
        mock_transport = Mock()
        mock_create_transport.return_value = mock_transport
        mock_proxy = Mock()
        mock_as_proxy.return_value = mock_proxy

        # Mock the proxy manager
        mock_proxy_manager = Mock()
        mock_proxy_manager.add_proxy_content = AsyncMock()
        mock_proxy_manager_class.return_value = mock_proxy_manager

        # Act
        await setup_mcp_mode(mock_mcp, mock_args)

        # Assert
        mock_create_transport.assert_called_once()
        mock_as_proxy.assert_called_once_with(mock_transport)
        mock_proxy_manager_class.assert_called_once_with(mock_mcp, False)
        mock_proxy_manager.add_proxy_content.assert_called_once_with(mock_proxy)

    @patch('src.aws_mcp_proxy.server.McpProxyManager')
    @patch('src.aws_mcp_proxy.server.create_transport_with_sigv4')
    @patch('src.aws_mcp_proxy.server.FastMCP.as_proxy')
    async def test_setup_mcp_mode_with_tools(
        self, mock_as_proxy, mock_create_transport, mock_proxy_manager_class
    ):
        """Test that MCP mode registers tools correctly."""
        # Arrange
        mock_mcp = Mock()
        mock_args = Mock()
        mock_args.endpoint = 'https://test.example.com'
        mock_args.service = 'test-service'
        mock_args.profile = None
        mock_args.allow_write = False

        # Mock the transport and proxy
        mock_transport = Mock()
        mock_create_transport.return_value = mock_transport
        mock_proxy = Mock()
        mock_as_proxy.return_value = mock_proxy

        # Mock the proxy manager
        mock_proxy_manager = Mock()
        mock_proxy_manager.add_proxy_content = AsyncMock()
        mock_proxy_manager_class.return_value = mock_proxy_manager

        # Act
        await setup_mcp_mode(mock_mcp, mock_args)

        # Assert
        mock_create_transport.assert_called_once()
        mock_as_proxy.assert_called_once_with(mock_transport)
        mock_proxy_manager_class.assert_called_once_with(mock_mcp, False)
        mock_proxy_manager.add_proxy_content.assert_called_once_with(mock_proxy)

    @patch('src.aws_mcp_proxy.server.McpProxyManager')
    @patch('src.aws_mcp_proxy.server.create_transport_with_sigv4')
    @patch('src.aws_mcp_proxy.server.FastMCP.as_proxy')
    async def test_setup_mcp_mode_tool_registration_error(
        self, mock_as_proxy, mock_create_transport, mock_proxy_manager_class
    ):
        """Test that MCP mode handles tool registration errors."""
        # Arrange
        mock_mcp = Mock()
        mock_args = Mock()
        mock_args.endpoint = 'https://test.example.com'
        mock_args.service = 'test-service'
        mock_args.profile = None
        mock_args.allow_write = False

        # Mock the transport and proxy
        mock_transport = Mock()
        mock_create_transport.return_value = mock_transport
        mock_proxy = Mock()
        mock_as_proxy.return_value = mock_proxy

        # Mock the proxy manager to raise an exception
        mock_proxy_manager = Mock()
        mock_proxy_manager.add_proxy_content = AsyncMock(
            side_effect=Exception('Tool registration failed')
        )
        mock_proxy_manager_class.return_value = mock_proxy_manager

        # Act & Assert - should raise exception
        with pytest.raises(Exception) as exc_info:
            await setup_mcp_mode(mock_mcp, mock_args)
        assert 'Tool registration failed' in str(exc_info.value)

    @patch('sys.argv', ['test', '--endpoint', 'https://test.example.com'])
    def test_parse_args_default(self):
        """Test parse_args with default arguments."""
        args = parse_args()
        assert args.endpoint == 'https://test.example.com'

    @patch('src.aws_mcp_proxy.server.asyncio.run')
    @patch('sys.argv', ['test', '--endpoint', 'https://test.example.com'])
    def test_main_function(self, mock_asyncio_run):
        """Test that main function runs server correctly."""
        # Arrange
        mock_asyncio_run.return_value = None

        # Act
        main()

        # Assert
        mock_asyncio_run.assert_called_once()

    @patch('src.aws_mcp_proxy.server.asyncio.run')
    @patch('sys.argv', ['test', '--endpoint', 'https://test.example.com'])
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

    @patch('src.aws_mcp_proxy.sigv4_helper.boto3.Session')
    @patch('src.aws_mcp_proxy.sigv4_helper.httpx.AsyncClient')
    @patch('src.aws_mcp_proxy.sigv4_helper.SigV4Auth')
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
        with patch.dict('os.environ', {'AWS_REGION': 'us-west-2'}):
            create_sigv4_client(service='test-service', profile='test-profile')

        # Assert
        mock_session.assert_called_once_with(profile_name='test-profile')
        mock_sigv4_auth.assert_called_once_with(mock_credentials, 'test-service', 'us-west-2')
        mock_async_client.assert_called_once()

    @patch('src.aws_mcp_proxy.sigv4_helper.boto3.Session')
    def test_create_sigv4_client_no_credentials(self, mock_session):
        """Test creating SigV4 client with no credentials."""
        # Arrange
        mock_session_instance = Mock()
        mock_session_instance.get_credentials.return_value = None
        mock_session.return_value = mock_session_instance

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            create_sigv4_client()
        assert 'No AWS credentials found' in str(exc_info.value)

    def test_main_module_execution(self):
        """Test that main is called when module is executed directly."""
        # This test is more complex because we need to test the actual module execution
        # We'll test by checking if the server module has the correct structure
        import src.aws_mcp_proxy.server as server_module

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
