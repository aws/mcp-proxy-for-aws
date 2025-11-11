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
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client
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
        with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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
            with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
                mock_auth = Mock()
                mock_auth_cls.return_value = mock_auth
                mock_stream_client.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write, mock_get_session)
                )
                mock_stream_client.return_value.__aexit__ = AsyncMock(return_value=None)

                async with aws_iam_streamablehttp_client(
                    endpoint='https://test.example.com/mcp',
                    aws_service=service_name,
                    aws_region=region,
                ):
                    pass

                mock_auth_cls.assert_called_once_with(
                    # Auth should be constructed with the resolved credentials, service, and region,
                    # and passed into the streamable client.
                    mock_session.get_credentials.return_value,
                    service_name,
                    region,
                )
                assert mock_stream_client.call_args[1]['auth'] is mock_auth


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
        with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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
            ):
                pass

            call_kwargs = mock_stream_client.call_args[1]
            # Confirm each parameter is forwarded unchanged.
            assert call_kwargs['url'] == 'https://test.example.com/mcp'
            assert call_kwargs['headers'] == headers
            assert call_kwargs['timeout'] == timeout_value
            assert call_kwargs['sse_read_timeout'] == sse_value
            assert call_kwargs['terminate_on_close'] == terminate_value


@pytest.mark.asyncio
async def test_custom_httpx_client_factory_is_passed(mock_session, mock_streams):
    """Test the passing of a custom HTTPX client factory."""
    # The factory should be handed through to the underlying streamable client untouched.
    mock_read, mock_write, mock_get_session = mock_streams
    custom_factory = Mock()

    with patch('boto3.Session', return_value=mock_session):
        with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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

            assert mock_stream_client.call_args[1]['httpx_client_factory'] is custom_factory


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
        with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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
        with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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
            with patch('mcp_proxy_for_aws.client.streamablehttp_client') as mock_stream_client:
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
