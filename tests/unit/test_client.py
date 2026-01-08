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

"""Unit tests for the client, parameterized by internal call."""

import pytest
from botocore.credentials import Credentials
from datetime import timedelta
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client, aws_iam_streamable_http_client
from unittest.mock import AsyncMock, Mock, patch


@pytest.fixture
def mock_session():
    """Mock boto3 session with credentials."""
    session = Mock()
    credentials = Mock()
    credentials.access_key = 'test_access_key'
    credentials.secret_key = 'test_secret_key'
    credentials.token = 'test_token'
    session.get_credentials.return_value = credentials
    session.profile_name = 'default'
    session.region_name = 'us-west-2'
    return session


@pytest.fixture
def mock_streams():
    """Mock stream components."""
    # Returns (read_stream, write_stream, get_session_id) to mimic the client context manager.
    return AsyncMock(), AsyncMock(), Mock(return_value='test-session-id')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'aws_region, aws_profile, expected_kwargs',
    [
        (None, None, {}),
        ('eu-west-1', None, {'region_name': 'eu-west-1'}),
        (None, 'my-profile', {'profile_name': 'my-profile'}),
        ('ap-southeast-1', 'prod', {'region_name': 'ap-southeast-1', 'profile_name': 'prod'}),
    ],
)
async def test_boto3_session_parameters(
    mock_session, mock_streams, aws_region, aws_profile, expected_kwargs
):
    """Test the correctness of boto3.Session parameters: region and profile."""
    # Validate that aws_iam_streamablehttp_client passes region/profile correctly to boto3.Session.
    mock_read, mock_write, mock_get_session = mock_streams

    with patch('boto3.Session', return_value=mock_session) as mock_boto:
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

            async with aws_iam_streamablehttp_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
                aws_region=aws_region,
                aws_profile=aws_profile,
            ):
                pass

    mock_boto.assert_called_once_with(**expected_kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'service_name, region',
    [
        ('bedrock-agentcore', 'us-west-2'),
        ('execute-api', 'us-east-1'),
    ],
)
async def test_sigv4_auth_is_created_and_used(mock_session, mock_streams, service_name, region):
    """Test the creation and wiring of SigV4HTTPXAuth with credentials, service, and region."""
    mock_read, mock_write, mock_get_session = mock_streams

    # Ensure the mocked session reflects the requested region
    mock_session.region_name = region

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth') as mock_auth_cls:
            with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
                mock_auth = Mock()
                mock_auth_cls.return_value = mock_auth
                
                # Mock the factory to capture its calls
                mock_http_client = Mock()
                mock_factory = Mock(return_value=mock_http_client)
                
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamablehttp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service=service_name,
                    aws_region=region,
                    httpx_client_factory=mock_factory,
                ):
                    pass

                mock_auth_cls.assert_called_once_with(
                    # Auth should be constructed with the resolved credentials, service, and region,
                    # and passed to the httpx client factory.
                    mock_session.get_credentials.return_value,
                    service_name,
                    region,
                )
                # Check that factory was called with auth
                assert mock_factory.called
                assert mock_factory.call_args[1]['auth'] is mock_auth
                # Check that http_client was passed to streamable_http_client
                assert mock_stream_client.call_args[1]['http_client'] is mock_http_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'headers, timeout_value, sse_value, terminate_value',
    [
        (None, 30, 300, True),
        ({'X-Custom': 'value'}, 60.5, 600.0, False),
        ({'A': 'B'}, timedelta(minutes=2), timedelta(minutes=5), True),
    ],
)
async def test_streamable_client_parameters(
    mock_session, mock_streams, headers, timeout_value, sse_value, terminate_value
):
    """Test the correctness of streamablehttp_client parameters."""
    # Verify that connection settings are forwarded as-is to the streamable HTTP client.
    # timedelta values are allowed and compared directly here.
    mock_read, mock_write, mock_get_session = mock_streams

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            mock_http_client = Mock()
            mock_factory = Mock(return_value=mock_http_client)
            
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

            async with aws_iam_streamablehttp_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
                headers=headers,
                timeout=timeout_value,
                sse_read_timeout=sse_value,
                terminate_on_close=terminate_value,
                httpx_client_factory=mock_factory,
            ):
                pass

            # Check that factory was called with headers and timeout
            assert mock_factory.called
            factory_kwargs = mock_factory.call_args[1]
            assert factory_kwargs['headers'] == headers
            # Check timeout conversion
            if isinstance(timeout_value, timedelta):
                expected_timeout = timeout_value.total_seconds()
            else:
                expected_timeout = timeout_value
            if isinstance(sse_value, timedelta):
                expected_sse_timeout = sse_value.total_seconds()
            else:
                expected_sse_timeout = sse_value
            # httpx.Timeout - all except read should be timeout_value, read should be sse_read_timeout
            assert factory_kwargs['timeout'].connect == expected_timeout
            assert factory_kwargs['timeout'].read == expected_sse_timeout
            assert factory_kwargs['timeout'].write == expected_timeout
            assert factory_kwargs['timeout'].pool == expected_timeout
            
            # Check streamable_http_client was called correctly
            stream_kwargs = mock_stream_client.call_args[1]
            assert stream_kwargs['url'] == 'https://test.example.com/mcp'
            assert stream_kwargs['http_client'] is mock_http_client
            assert stream_kwargs['terminate_on_close'] == terminate_value


@pytest.mark.asyncio
async def test_custom_httpx_client_factory_is_passed(mock_session, mock_streams):
    """Test the passing of a custom HTTPX client factory."""
    # The factory should be handed through to the underlying streamable client untouched.
    mock_read, mock_write, mock_get_session = mock_streams
    custom_factory = Mock()

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            mock_http_client = Mock()
            custom_factory.return_value = mock_http_client
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

            async with aws_iam_streamablehttp_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
                httpx_client_factory=custom_factory,
            ):
                pass

            # Check that the custom factory was called
            assert custom_factory.called
            # Check that the http_client from custom factory was passed to streamable_http_client
            assert mock_stream_client.call_args[1]['http_client'] is mock_http_client


@pytest.mark.asyncio
async def test_context_manager_cleanup(mock_session, mock_streams):
    """Test the context manager cleanup."""
    # Replace __aexit__ to observe that it is invoked when exiting the async with-block.
    mock_read, mock_write, mock_get_session = mock_streams
    cleanup_called = False

    async def mock_aexit(*_):
        nonlocal cleanup_called
        cleanup_called = True

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = mock_aexit

            async with aws_iam_streamablehttp_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
            ):
                pass

            assert cleanup_called


@pytest.mark.asyncio
async def test_credentials_parameter_with_region(mock_streams):
    """Test using provided credentials with aws_region."""
    mock_read, mock_write, mock_get_session = mock_streams
    creds = Credentials('test_key', 'test_secret', 'test_token')

    with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth') as mock_auth_cls:
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            mock_auth = Mock()
            mock_auth_cls.return_value = mock_auth
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

            async with aws_iam_streamablehttp_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
                aws_region='us-east-1',
                credentials=creds,
            ):
                pass

            mock_auth_cls.assert_called_once_with(creds, 'bedrock-agentcore', 'us-east-1')


@pytest.mark.asyncio
async def test_credentials_parameter_without_region_raises_error():
    """Test that using credentials without aws_region raises ValueError."""
    creds = Credentials('test_key', 'test_secret', 'test_token')

    with pytest.raises(
        ValueError,
        match='AWS region must be specified via aws_region parameter when using credentials',
    ):
        async with aws_iam_streamablehttp_client(
            endpoint='https://test.example.com/mcp',
            aws_service='bedrock-agentcore',
            credentials=creds,
        ):
            pass


@pytest.mark.asyncio
async def test_credentials_parameter_bypasses_boto3_session(mock_streams):
    """Test that providing credentials bypasses boto3.Session creation."""
    mock_read, mock_write, mock_get_session = mock_streams
    creds = Credentials('test_key', 'test_secret', 'test_token')

    with patch('boto3.Session') as mock_boto:
        with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth'):
            with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamablehttp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_region='us-west-2',
                    credentials=creds,
                ):
                    pass

                mock_boto.assert_not_called()


# Tests for the new aws_iam_streamable_http_client function


@pytest.mark.asyncio
async def test_new_client_with_http_client_provided(mock_streams):
    """Test that providing http_client uses it directly without creating auth."""
    mock_read, mock_write, mock_get_session = mock_streams
    mock_http_client = Mock()

    with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
        with patch('boto3.Session') as mock_boto:
            with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth') as mock_auth_cls:
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamable_http_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                    aws_region='us-west-2',
                    http_client=mock_http_client,
                ):
                    pass

                # Should not create boto3 session or auth when http_client is provided
                mock_boto.assert_not_called()
                mock_auth_cls.assert_not_called()
                
                # Should pass the provided client to streamable_http_client
                assert mock_stream_client.call_args[1]['http_client'] is mock_http_client
                assert mock_stream_client.call_args[1]['url'] == 'https://test.example.com/mcp'


@pytest.mark.asyncio
async def test_new_client_with_credentials_and_region(mock_streams):
    """Test the new client with provided credentials and region."""
    mock_read, mock_write, mock_get_session = mock_streams
    creds = Credentials('new_key', 'new_secret', 'new_token')

    with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth') as mock_auth_cls:
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            with patch('httpx.AsyncClient') as mock_client_cls:
                mock_auth = Mock()
                mock_auth_cls.return_value = mock_auth
                mock_client = Mock()
                mock_client_cls.return_value = mock_client
                
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamable_http_client(
                    endpoint='https://new.example.com/mcp',
                    aws_service='execute-api',
                    aws_region='eu-west-1',
                    credentials=creds,
                ):
                    pass

                # Should create auth with provided credentials
                mock_auth_cls.assert_called_once_with(creds, 'execute-api', 'eu-west-1')
                
                # Should create httpx client with auth and default headers
                mock_client_cls.assert_called_once_with(
                    auth=mock_auth,
                    headers={'Accept': 'application/json, text/event-stream'}
                )
                
                # Should pass the created client to streamable_http_client
                assert mock_stream_client.call_args[1]['http_client'] is mock_client


@pytest.mark.asyncio
async def test_new_client_without_credentials_uses_boto3(mock_streams):
    """Test that new client without credentials uses boto3.Session."""
    mock_read, mock_write, mock_get_session = mock_streams
    
    # Create a custom mock session for this test
    mock_session = Mock()
    credentials = Mock()
    credentials.access_key = 'test_access_key'
    credentials.secret_key = 'test_secret_key'
    credentials.token = 'test_token'
    mock_session.get_credentials.return_value = credentials
    mock_session.profile_name = 'test-profile'
    mock_session.region_name = 'ap-south-1'  # Use the region we're testing with

    with patch('boto3.Session', return_value=mock_session) as mock_boto:
        with patch('mcp_proxy_for_aws.client.SigV4HTTPXAuth') as mock_auth_cls:
            with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
                with patch('httpx.AsyncClient'):
                    mock_auth = Mock()
                    mock_auth_cls.return_value = mock_auth
                    
                    mock_stream_client.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read, mock_write, mock_get_session)
                    )
                    mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                    async with aws_iam_streamable_http_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='bedrock-agentcore',
                        aws_region='ap-south-1',
                        aws_profile='test-profile',
                    ):
                        pass

                    # Should create boto3 session with region and profile
                    mock_boto.assert_called_once_with(
                        region_name='ap-south-1',
                        profile_name='test-profile'
                    )
                    
                    # Should use credentials from session
                    mock_auth_cls.assert_called_once_with(
                        mock_session.get_credentials.return_value,
                        'bedrock-agentcore',
                        'ap-south-1'
                    )


@pytest.mark.asyncio
async def test_new_client_credentials_without_region_raises():
    """Test that new client with credentials but no region raises ValueError."""
    creds = Credentials('key', 'secret', 'token')

    with pytest.raises(
        ValueError,
        match='AWS region must be specified via aws_region parameter when using credentials'
    ):
        async with aws_iam_streamable_http_client(
            endpoint='https://test.example.com/mcp',
            aws_service='bedrock-agentcore',
            credentials=creds,
        ):
            pass


@pytest.mark.asyncio
async def test_new_client_without_region_in_session_raises():
    """Test that new client raises when region cannot be determined from session."""
    mock_session = Mock()
    mock_session.get_credentials.return_value = Mock()
    mock_session.region_name = None

    with pytest.raises(
        ValueError,
        match='AWS region must be specified via aws_region parameter,  AWS_REGION environment variable, or AWS config'
    ):
        with patch('boto3.Session', return_value=mock_session):
            async with aws_iam_streamable_http_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
            ):
                pass


@pytest.mark.asyncio
async def test_new_client_terminate_on_close_parameter(mock_streams):
    """Test that terminate_on_close parameter is passed correctly."""
    mock_read, mock_write, mock_get_session = mock_streams
    mock_http_client = Mock()

    with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
        mock_stream_client.return_value.__aenter__ = AsyncMock(
            return_value=(mock_read, mock_write, mock_get_session)
        )
        mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

        # Test with terminate_on_close=False
        async with aws_iam_streamable_http_client(
            endpoint='https://test.example.com/mcp',
            aws_service='bedrock-agentcore',
            aws_region='us-west-2',
            http_client=mock_http_client,
            terminate_on_close=False,
        ):
            pass

        assert mock_stream_client.call_args[1]['terminate_on_close'] is False


@pytest.mark.asyncio
async def test_new_client_returns_streams_tuple(mock_session, mock_streams):
    """Test that new client returns the correct streams tuple."""
    mock_read, mock_write, mock_get_session = mock_streams

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            with patch('httpx.AsyncClient'):
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamable_http_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service='bedrock-agentcore',
                ) as (read_stream, write_stream, get_session_id):
                    assert read_stream is mock_read
                    assert write_stream is mock_write
                    assert get_session_id is mock_get_session


@pytest.mark.asyncio
async def test_new_client_logging_debug_messages(mock_session, mock_streams):
    """Test that new client logs appropriate debug messages."""
    mock_read, mock_write, mock_get_session = mock_streams

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
            with patch('httpx.AsyncClient'):
                with patch('mcp_proxy_for_aws.client.logger') as mock_logger:
                    mock_stream_client.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read, mock_write, mock_get_session)
                    )
                    mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                    async with aws_iam_streamable_http_client(
                        endpoint='https://test.example.com/mcp',
                        aws_service='my-service',
                        aws_region='my-region',
                    ):
                        pass

                    # Check that debug logging was called
                    assert mock_logger.debug.called
                    # Verify specific log messages
                    debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
                    assert any('Preparing AWS IAM MCP client' in msg for msg in debug_calls)
                    assert any('AWS region' in msg for msg in debug_calls)
                    assert any('AWS service' in msg for msg in debug_calls)


@pytest.mark.asyncio
async def test_new_client_with_provided_http_client_logs_correctly(mock_streams):
    """Test that providing http_client logs the appropriate message."""
    mock_read, mock_write, mock_get_session = mock_streams
    mock_http_client = Mock()

    with patch('mcp_proxy_for_aws.client.streamable_http_client') as mock_stream_client:
        with patch('mcp_proxy_for_aws.client.logger') as mock_logger:
            mock_stream_client.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_get_session)
            )
            mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

            async with aws_iam_streamable_http_client(
                endpoint='https://test.example.com/mcp',
                aws_service='bedrock-agentcore',
                aws_region='us-west-2',
                http_client=mock_http_client,
            ):
                pass

            # Should log about using provided http_client
            debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
            assert any('Using provided http_client' in msg for msg in debug_calls)
