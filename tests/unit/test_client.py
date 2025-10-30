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

"""Unit tests for the AWS IAM MCP client."""

import pytest
import logging 

from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch
from mcp_proxy_for_aws.client import aws_iam_mcp_client


class TestAwsIamMcpClient:
    """Test cases for the aws_iam_mcp_client async context manager."""

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_basic(self):
        """Test basic creation of AWS IAM MCP client with minimal parameters."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock(return_value='test-session-id')

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test the context manager
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                ) as (read_stream, write_stream, get_session_id):
                    # Verify returned components
                    assert read_stream == mock_read_stream
                    assert write_stream == mock_write_stream
                    assert get_session_id == mock_get_session_id

                    # Verify session ID can be retrieved
                    session_id = get_session_id()
                    assert session_id == 'test-session-id'

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_with_all_parameters(self):
        """Test AWS IAM MCP client with all optional parameters specified."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'test-profile'
        mock_session.region_name = 'eu-west-1'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock(return_value='session-123')

        custom_headers = {'X-Custom-Header': 'test-value'}
        custom_timeout = timedelta(seconds=60)
        custom_sse_timeout = timedelta(seconds=600)

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with all parameters
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_region='eu-west-1',
                    aws_profile='test-profile',
                    headers=custom_headers,
                    timeout=custom_timeout,
                    sse_read_timeout=custom_sse_timeout,
                    terminate_on_close=False,
                ) as (read_stream, write_stream, get_session_id):
                    # Verify returned components
                    assert read_stream == mock_read_stream
                    assert write_stream == mock_write_stream
                    assert get_session_id == mock_get_session_id

                # Verify streamablehttp_client was called with correct parameters
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['url'] == 'https://test.example.com/mcp'
                assert call_kwargs['headers'] == custom_headers
                assert call_kwargs['timeout'] == custom_timeout
                assert call_kwargs['sse_read_timeout'] == custom_sse_timeout
                assert call_kwargs['terminate_on_close'] is False

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_with_aws_region(self):
        """Test that AWS region is properly used when provided."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'ap-southeast-1'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session) as mock_boto_session:
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with explicit region
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_region='ap-southeast-1',
                ):
                    pass

                # Verify boto3 Session was called with region_name
                mock_boto_session.assert_called_once_with(region_name='ap-southeast-1')

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_with_aws_profile(self):
        """Test that AWS profile is properly used when provided."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'my-profile'
        mock_session.region_name = 'us-east-1'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session) as mock_boto_session:
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with explicit profile
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_profile='my-profile',
                ):
                    pass

                # Verify boto3 Session was called with profile_name
                mock_boto_session.assert_called_once_with(profile_name='my-profile')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('region, profile', [
        (None, None), 
        ('eu-central-1', None), 
        (None, 'test-profile-1'),
        ('eu-central-1', 'test-profile-1')
    ])
    async def test_aws_iam_mcp_client_with_arguments(self, region, profile):
        """Test AWS IAM MCP client with different combinations of arguments."""
        # Setup mocks
        mock_session = Mock()
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        endpoint = 'https://test.example.com/mcp'
        service = 'bedrock-agentcore'

        with patch('boto3.Session', return_value=mock_session) as mock_boto_session:
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with both region and profile
                async with aws_iam_mcp_client(endpoint=endpoint, aws_service=service, aws_region=region, aws_profile=profile):
                    expected_kwargs = {}
                    if region:
                        expected_kwargs['region_name'] = region
                    if profile:
                        expected_kwargs['profile_name'] = profile

                    # Verify boto3 Session was called with both parameters
                    mock_boto_session.assert_called_once_with(**expected_kwargs)

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_sigv4_auth_creation(self):
        """Test that SigV4 authentication is properly created."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.SigV4HTTPXAuth'
            ) as mock_sigv4_auth_class:
                with patch(
                    'mcp_proxy_for_aws.client.streamablehttp_client'
                ) as mock_streamable_client:
                    # Setup mocks
                    mock_auth_instance = Mock()
                    mock_sigv4_auth_class.return_value = mock_auth_instance
                    mock_streamable_client.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                    )
                    mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Test
                    async with aws_iam_mcp_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='bedrock-agentcore',
                        aws_region='us-west-2',
                    ):
                        pass

                    # Verify SigV4HTTPXAuth was created with correct parameters
                    mock_sigv4_auth_class.assert_called_once_with(
                        mock_credentials, 'bedrock-agentcore', 'us-west-2'
                    )

                    # Verify auth was passed to streamablehttp_client
                    call_kwargs = mock_streamable_client.call_args[1]
                    assert call_kwargs['auth'] == mock_auth_instance

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_timeout_as_float(self):
        """Test that timeout can be specified as a float."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with float timeout
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    timeout=45.5,
                    sse_read_timeout=450.0,
                ):
                    pass

                # Verify timeouts were passed correctly
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['timeout'] == 45.5
                assert call_kwargs['sse_read_timeout'] == 450.0

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_timeout_as_timedelta(self):
        """Test that timeout can be specified as a timedelta."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        timeout_td = timedelta(minutes=2)
        sse_timeout_td = timedelta(minutes=15)

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with timedelta timeout
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    timeout=timeout_td,
                    sse_read_timeout=sse_timeout_td,
                ):
                    pass

                # Verify timeouts were passed correctly
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['timeout'] == timeout_td
                assert call_kwargs['sse_read_timeout'] == sse_timeout_td

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_custom_httpx_factory(self):
        """Test that a custom HTTPX client factory can be provided."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        # Custom factory mock
        mock_custom_factory = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with custom factory
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    httpx_client_factory=mock_custom_factory,
                ):
                    pass

                # Verify custom factory was passed
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['httpx_client_factory'] == mock_custom_factory

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_logging(self, caplog):
        """Test that appropriate log messages are generated."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'test-profile'
        mock_session.region_name = 'us-east-1'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with logging enabled
                with caplog.at_level(logging.INFO):
                    async with aws_iam_mcp_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='bedrock-agentcore',
                        aws_region='us-east-1',
                        aws_profile='test-profile',
                    ):
                        pass

                # Verify log messages
                log_messages = [record.message for record in caplog.records]
                assert any(
                    'Preparing AWS IAM MCP client' in msg
                    and 'https://test.example.com/mcp' in msg
                    for msg in log_messages
                )
                assert any(
                    'Successfully prepared AWS IAM MCP client' in msg
                    and 'https://test.example.com/mcp' in msg
                    for msg in log_messages
                )

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_logging_debug(self, caplog):
        """Test that debug log messages include AWS configuration details."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'debug-profile'
        mock_session.region_name = 'ap-northeast-1'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with debug logging enabled
                with caplog.at_level(logging.DEBUG):
                    async with aws_iam_mcp_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='bedrock-agentcore',
                        aws_region='ap-northeast-1',
                        aws_profile='debug-profile',
                    ):
                        pass

                # Verify debug log messages
                log_messages = [record.message for record in caplog.records]
                assert any('AWS profile: debug-profile' in msg for msg in log_messages)
                assert any('AWS region: ap-northeast-1' in msg for msg in log_messages)
                assert any('AWS service: bedrock-agentcore' in msg for msg in log_messages)

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_context_manager_cleanup(self):
        """Test that the context manager properly cleans up resources."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        # Track cleanup
        cleanup_called = False

        async def mock_aexit(*args):
            nonlocal cleanup_called
            cleanup_called = True

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = mock_aexit

                # Test context manager cleanup
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                ):
                    pass

                # Verify cleanup was called
                assert cleanup_called

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_with_none_optional_parameters(self):
        """Test that None values for optional parameters are handled correctly."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with explicit None values
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_region=None,
                    aws_profile=None,
                    headers=None,
                ):
                    pass

                # Verify function handled None values correctly
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['headers'] is None

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_credentials_without_token(self):
        """Test that credentials without session token work correctly."""
        # Mock boto3 session with credentials without token
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None  # No session token
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.SigV4HTTPXAuth'
            ) as mock_sigv4_auth_class:
                with patch(
                    'mcp_proxy_for_aws.client.streamablehttp_client'
                ) as mock_streamable_client:
                    # Setup mocks
                    mock_auth_instance = Mock()
                    mock_sigv4_auth_class.return_value = mock_auth_instance
                    mock_streamable_client.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                    )
                    mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Test
                    async with aws_iam_mcp_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='bedrock-agentcore',
                    ):
                        pass

                    # Verify SigV4HTTPXAuth was called with credentials (even without token)
                    mock_sigv4_auth_class.assert_called_once()
                    call_args = mock_sigv4_auth_class.call_args[0]
                    assert call_args[0] == mock_credentials
                    assert call_args[0].token is None

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_default_timeout_values(self):
        """Test that default timeout values are applied correctly."""
        # Mock boto3 session
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_session.profile_name = 'default'
        mock_session.region_name = 'us-west-2'

        # Mock streamable HTTP client components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_get_session_id = Mock()

        with patch('boto3.Session', return_value=mock_session):
            with patch(
                'mcp_proxy_for_aws.client.streamablehttp_client'
            ) as mock_streamable_client:
                # Setup async context manager mock
                mock_streamable_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read_stream, mock_write_stream, mock_get_session_id)
                )
                mock_streamable_client.return_value.__aexit__ = AsyncMock(return_value=None)

                # Test with default timeout values
                async with aws_iam_mcp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                ):
                    pass

                # Verify default timeout values were used
                call_kwargs = mock_streamable_client.call_args[1]
                assert call_kwargs['timeout'] == 30  # Default timeout
                assert call_kwargs['sse_read_timeout'] == 300  # Default SSE timeout
                assert call_kwargs['terminate_on_close'] is True  # Default terminate_on_close

    @pytest.mark.asyncio
    async def test_aws_iam_mcp_client_different_service_names(self):
        """Test that different AWS service names are handled correctly."""
        test_services = [
            'bedrock-agentcore',
            'execute-api',
            'lambda',
            's3',
            'custom-service',
        ]

        for service_name in test_services:
            # Mock boto3 session
            mock_session = Mock()
            mock_credentials = Mock()
            mock_credentials.access_key = 'test_access_key'
            mock_credentials.secret_key = 'test_secret_key'
            mock_credentials.token = None
            mock_session.get_credentials.return_value = mock_credentials
            mock_session.profile_name = 'default'
            mock_session.region_name = 'us-west-2'

            # Mock streamable HTTP client components
            mock_read_stream = AsyncMock()
            mock_write_stream = AsyncMock()
            mock_get_session_id = Mock()

            with patch('boto3.Session', return_value=mock_session):
                with patch(
                    'mcp_proxy_for_aws.client.SigV4HTTPXAuth'
                ) as mock_sigv4_auth_class:
                    with patch(
                        'mcp_proxy_for_aws.client.streamablehttp_client'
                    ) as mock_streamable_client:
                        # Setup mocks
                        mock_auth_instance = Mock()
                        mock_sigv4_auth_class.return_value = mock_auth_instance
                        mock_streamable_client.return_value.__aenter__ = AsyncMock(
                            return_value=(
                                mock_read_stream,
                                mock_write_stream,
                                mock_get_session_id,
                            )
                        )
                        mock_streamable_client.return_value.__aexit__ = AsyncMock(
                            return_value=None
                        )

                        # Test with different service name
                        async with aws_iam_mcp_client(
                            endpoint='https://test.example.com/mcp',
                            aws_service=service_name,
                        ):
                            pass

                        # Verify service name was used in SigV4 auth
                        call_args = mock_sigv4_auth_class.call_args[0]
                        assert call_args[1] == service_name
