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

"""Unit tests for sigv4_helper module."""

import httpx
import pytest
from mcp_proxy_for_aws.sigv4_helper import (
    SigV4HTTPXAuth,
    create_aws_session,
    create_sigv4_client,
)
from unittest.mock import Mock, patch


class TestSigV4HTTPXAuth:
    """Test cases for the SigV4HTTPXAuth class."""

    @pytest.mark.asyncio
    async def test_auth_flow_signs_request(self):
        """Test that auth_flow properly signs requests."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create a test request
        request = httpx.Request('GET', 'https://example.com/test', headers={'Host': 'example.com'})

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Get signed request from auth flow
        auth_flow = auth.auth_flow(request)
        signed_request = next(auth_flow)

        # Verify request was signed (check for required SigV4 headers)
        assert 'Authorization' in signed_request.headers
        assert 'X-Amz-Date' in signed_request.headers


class TestCreateAwsSession:
    """Test cases for the create_aws_session function."""

    @patch('boto3.Session')
    def test_create_aws_session_default(self, mock_session_class):
        """Test creating AWS session with default profile."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_session.get_credentials.return_value = mock_credentials
        mock_session_class.return_value = mock_session

        # Test session creation
        result = create_aws_session()

        # Verify session was created correctly
        mock_session_class.assert_called_once_with()
        assert result == mock_session

    @patch('boto3.Session')
    def test_create_aws_session_with_profile(self, mock_session_class):
        """Test creating AWS session with specific profile."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_session.get_credentials.return_value = mock_credentials
        mock_session_class.return_value = mock_session

        # Test session creation with profile
        result = create_aws_session(profile='test-profile')

        # Verify session was created with profile
        mock_session_class.assert_called_once_with(profile_name='test-profile')
        assert result == mock_session

    @patch('boto3.Session')
    def test_create_aws_session_no_credentials(self, mock_session_class):
        """Test error handling when no credentials are available."""
        # Mock session with no credentials
        mock_session = Mock()
        mock_session.get_credentials.return_value = None
        mock_session_class.return_value = mock_session

        # Test that ValueError is raised
        with pytest.raises(ValueError) as exc_info:
            create_aws_session()

        assert 'No AWS credentials found' in str(exc_info.value)

    @patch('boto3.Session')
    def test_create_aws_session_creation_failure(self, mock_session_class):
        """Test error handling when session creation fails."""
        # Mock session creation failure
        mock_session_class.side_effect = Exception('Session creation failed')

        # Test that ValueError is raised
        with pytest.raises(ValueError) as exc_info:
            create_aws_session(profile='invalid-profile')

        assert 'Failed to create AWS session' in str(exc_info.value)
        assert 'invalid-profile' in str(exc_info.value)


class TestCreateSigv4Client:
    """Test cases for the create_sigv4_client function."""

    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_default(self, mock_client_class):
        """Test creating SigV4 client with default parameters."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation
        result = create_sigv4_client(service='test-service', region='test-region')

        # Check that AsyncClient was called with correct parameters
        call_args = mock_client_class.call_args
        assert 'auth' not in call_args[1], 'Auth should not be used, signing via hooks'
        assert 'event_hooks' in call_args[1]
        assert 'response' in call_args[1]['event_hooks']
        assert 'request' in call_args[1]['event_hooks']
        assert len(call_args[1]['event_hooks']['response']) == 1
        assert len(call_args[1]['event_hooks']['request']) == 2  # metadata + sign hooks
        assert call_args[1]['headers']['Accept'] == 'application/json, text/event-stream'
        assert result == mock_client

    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_headers(self, mock_client_class):
        """Test creating SigV4 client with custom headers."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with custom headers
        custom_headers = {'Custom-Header': 'custom-value'}
        result = create_sigv4_client(
            service='test-service', region='test-region', headers=custom_headers
        )

        # Verify client was created with merged headers
        call_args = mock_client_class.call_args
        expected_headers = {
            'Accept': 'application/json, text/event-stream',
            'Custom-Header': 'custom-value',
        }
        assert call_args[1]['headers'] == expected_headers
        assert result == mock_client

    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_service_and_region(self, mock_client_class):
        """Test creating SigV4 client with custom service and region."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with custom parameters
        result = create_sigv4_client(
            service='custom-service', profile='test-profile', region='us-east-1'
        )

        # Verify client was created
        assert result == mock_client

    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_kwargs(self, mock_client_class):
        """Test creating SigV4 client with additional kwargs."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with additional kwargs
        result = create_sigv4_client(
            service='test-service',
            region='test-region',
            verify=False,
            proxies={'http': 'http://proxy:8080'},
        )

        # Verify client was created with additional kwargs
        call_args = mock_client_class.call_args
        assert call_args[1]['verify'] is False
        assert call_args[1]['proxies'] == {'http': 'http://proxy:8080'}
        assert result == mock_client

    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_prompt_context(self, mock_client_class):
        """Test creating SigV4 client when prompts exist in the system context.

        This test simulates the scenario where the sigv4_helper is used in a context
        where MCP prompts are present, ensuring the client is properly configured
        to handle requests that might include prompt-related content or headers.
        """
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with headers that might be used when prompts exist
        prompt_context_headers = {
            'X-MCP-Prompt-Context': 'enabled',
            'Content-Type': 'application/json',
        }

        result = create_sigv4_client(
            service='test-service', headers=prompt_context_headers, region='us-west-2'
        )

        # Check that AsyncClient was called with correct parameters including prompt headers
        call_args = mock_client_class.call_args

        # Verify headers include both default and prompt-context headers
        expected_headers = {
            'Accept': 'application/json, text/event-stream',
            'X-MCP-Prompt-Context': 'enabled',
            'Content-Type': 'application/json',
        }
        assert call_args[1]['headers'] == expected_headers

        # Verify error handling hook is present for prompt-related error responses
        assert 'event_hooks' in call_args[1]
        assert 'response' in call_args[1]['event_hooks']
        assert len(call_args[1]['event_hooks']['response']) == 1

        assert result == mock_client
