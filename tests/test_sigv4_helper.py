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
import json
import os
import pytest
from src.aws_mcp_proxy.sigv4_helper import (
    SigV4HTTPXAuth,
    _handle_error_response,
    create_aws_session,
    create_sigv4_auth,
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


class TestHandleErrorResponse:
    """Test cases for the _handle_error_response function."""

    @pytest.mark.asyncio
    async def test_handle_error_response_with_json_error(self):
        """Test error handling with JSON error response."""
        # Create a mock error response with JSON content
        request = httpx.Request('GET', 'https://example.com/test')
        error_data = {'error': 'Not Found', 'message': 'The requested resource was not found'}
        response = httpx.Response(
            status_code=404,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )

        # Test that the function raises HTTPStatusError with enhanced message
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await _handle_error_response(response)

        # Verify the error message contains the JSON details
        error_msg = str(exc_info.value)
        assert '404' in error_msg
        assert 'Not Found' in error_msg
        assert 'https://example.com/test' in error_msg

    @pytest.mark.asyncio
    async def test_handle_error_response_with_non_json_error(self):
        """Test error handling with non-JSON error response."""
        # Create a mock error response with plain text content
        request = httpx.Request('GET', 'https://example.com/test')
        response = httpx.Response(
            status_code=500,
            headers={'content-type': 'text/plain'},
            content=b'Internal Server Error',
            request=request,
        )

        # Test that the function raises HTTPStatusError
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await _handle_error_response(response)

        # Verify the error contains status code information
        assert exc_info.value.response.status_code == 500

    @pytest.mark.asyncio
    async def test_handle_error_response_with_success_response(self):
        """Test that successful responses don't raise errors."""
        # Create a mock success response
        request = httpx.Request('GET', 'https://example.com/test')
        response = httpx.Response(
            status_code=200,
            headers={'content-type': 'application/json'},
            content=b'{"success": true}',
            request=request,
        )

        # Test that no exception is raised for successful responses
        try:
            await _handle_error_response(response)
        except Exception as e:
            pytest.fail(f'Unexpected exception raised for success response: {e}')

    @pytest.mark.asyncio
    async def test_handle_error_response_with_read_failure(self):
        """Test error handling when response reading fails."""
        # Create a mock response that fails to read
        request = httpx.Request('GET', 'https://example.com/test')
        response = Mock(spec=httpx.Response)
        response.is_error = True
        response.aread = Mock(side_effect=Exception('Read failed'))
        response.json = Mock(side_effect=Exception('JSON parsing failed'))
        response.text = 'Mock error text'
        response.status_code = 500
        response.url = 'https://example.com/test'
        response.raise_for_status = Mock(
            side_effect=httpx.HTTPStatusError(
                message='HTTP Error', request=request, response=response
            )
        )

        # Test that the function still raises HTTPStatusError even when reading fails
        with pytest.raises(httpx.HTTPStatusError):
            await _handle_error_response(response)

    @pytest.mark.asyncio
    async def test_handle_error_response_with_invalid_json(self):
        """Test error handling with invalid JSON response."""
        # Create a mock error response with invalid JSON
        request = httpx.Request('GET', 'https://example.com/test')
        response = httpx.Response(
            status_code=400,
            headers={'content-type': 'application/json'},
            content=b'Invalid JSON content {',
            request=request,
        )

        # Test that the function raises HTTPStatusError even with invalid JSON
        with pytest.raises(httpx.HTTPStatusError):
            await _handle_error_response(response)


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


class TestCreateSigv4Auth:
    """Test cases for the create_sigv4_auth function."""

    @patch('src.aws_mcp_proxy.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_default(self, mock_create_session):
        """Test creating SigV4 auth with default parameters."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation
        result = create_sigv4_auth('test-service')

        # Verify auth was created correctly
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'us-west-2'  # default region
        assert result.credentials == mock_credentials

    @patch('src.aws_mcp_proxy.sigv4_helper.create_aws_session')
    @patch.dict(os.environ, {'AWS_REGION': 'eu-west-1'})
    def test_create_sigv4_auth_with_env_region(self, mock_create_session):
        """Test creating SigV4 auth with region from environment variable."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation
        result = create_sigv4_auth('test-service', profile='test-profile')

        # Verify auth was created with environment region
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'eu-west-1'  # from environment
        assert result.credentials == mock_credentials

    @patch('src.aws_mcp_proxy.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_with_explicit_region(self, mock_create_session):
        """Test creating SigV4 auth with explicit region parameter."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation with explicit region
        result = create_sigv4_auth('test-service', region='ap-southeast-1')

        # Verify auth was created with explicit region
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'ap-southeast-1'
        assert result.credentials == mock_credentials


class TestCreateSigv4Client:
    """Test cases for the create_sigv4_client function."""

    @patch('src.aws_mcp_proxy.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_default(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client with default parameters."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation
        result = create_sigv4_client()

        # Verify client was created correctly
        mock_create_auth.assert_called_once_with('eks-mcp', None, None)

        # Check that AsyncClient was called with correct parameters
        call_args = mock_client_class.call_args
        assert call_args[1]['auth'] == mock_auth
        assert 'event_hooks' in call_args[1]
        assert 'response' in call_args[1]['event_hooks']
        assert len(call_args[1]['event_hooks']['response']) == 1
        assert call_args[1]['headers']['Accept'] == 'application/json, text/event-stream'
        assert result == mock_client

    @patch('src.aws_mcp_proxy.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_headers(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client with custom headers."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with custom headers
        custom_headers = {'Custom-Header': 'custom-value'}
        result = create_sigv4_client(headers=custom_headers)

        # Verify client was created with merged headers
        call_args = mock_client_class.call_args
        expected_headers = {
            'Accept': 'application/json, text/event-stream',
            'Custom-Header': 'custom-value',
        }
        assert call_args[1]['headers'] == expected_headers
        assert result == mock_client

    @patch('src.aws_mcp_proxy.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_service_and_region(
        self, mock_client_class, mock_create_auth
    ):
        """Test creating SigV4 client with custom service and region."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with custom parameters
        result = create_sigv4_client(
            service='custom-service', profile='test-profile', region='us-east-1'
        )

        # Verify auth was created with custom parameters
        mock_create_auth.assert_called_once_with('custom-service', 'test-profile', 'us-east-1')
        assert result == mock_client

    @patch('src.aws_mcp_proxy.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_kwargs(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client with additional kwargs."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with additional kwargs
        result = create_sigv4_client(verify=False, proxies={'http': 'http://proxy:8080'})

        # Verify client was created with additional kwargs
        call_args = mock_client_class.call_args
        assert call_args[1]['verify'] is False
        assert call_args[1]['proxies'] == {'http': 'http://proxy:8080'}
        assert result == mock_client

    @patch('src.aws_mcp_proxy.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_prompt_context(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client when prompts exist in the system context.

        This test simulates the scenario where the sigv4_helper is used in a context
        where MCP prompts are present, ensuring the client is properly configured
        to handle requests that might include prompt-related content or headers.
        """
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation with headers that might be used when prompts exist
        prompt_context_headers = {
            'X-MCP-Prompt-Context': 'enabled',
            'Content-Type': 'application/json',
        }

        result = create_sigv4_client(
            service='eks-mcp', headers=prompt_context_headers, region='us-west-2'
        )

        # Verify client was created correctly with prompt context
        mock_create_auth.assert_called_once_with('eks-mcp', None, 'us-west-2')

        # Check that AsyncClient was called with correct parameters including prompt headers
        call_args = mock_client_class.call_args
        assert call_args[1]['auth'] == mock_auth

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
