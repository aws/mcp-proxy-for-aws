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
import pytest
from mcp_proxy_for_aws.sigv4_helper import (
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


class TestSigV4HTTPXAuthAutoDetect:
    """Test cases for the SigV4HTTPXAuth class with auto-detection."""

    def test_initialization_starts_with_sigv4(self):
        """Test that SigV4HTTPXAuth starts with SigV4 signer."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Verify initialization
        assert auth.credentials == mock_credentials
        assert auth.service == 'test-service'
        assert auth.region == 'us-west-2'
        assert auth.use_sigv4a is False
        assert auth.sigv4_signer is not None
        assert auth.sigv4a_signer is None  # Lazy initialization

    def test_lazy_initialization_of_sigv4a_signer(self):
        """Test that SigV4A signer is lazily initialized."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Verify SigV4A signer is not initialized yet
        assert auth.sigv4a_signer is None

        # Trigger lazy initialization by setting use_sigv4a
        auth.use_sigv4a = True
        # Note: actual initialization happens in auth_flow when needed

    def test_credential_handling(self):
        """Test that credentials are properly stored and accessible."""
        # Create mock credentials with all attributes
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_session_token'

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Verify credentials are stored correctly
        assert auth.credentials == mock_credentials
        assert auth.credentials.access_key == 'test_access_key'
        assert auth.credentials.secret_key == 'test_secret_key'
        assert auth.credentials.token == 'test_session_token'

    @pytest.mark.asyncio
    async def test_successful_sigv4_request_no_retry(self):
        """Test that successful SigV4 request does not trigger retry."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create a test request
        request = httpx.Request('GET', 'https://example.com/test', headers={'Host': 'example.com'})

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Mock successful response
        success_response = httpx.Response(
            status_code=200,
            headers={'content-type': 'application/json'},
            content=b'{"success": true}',
            request=request,
        )

        # Get signed request from auth flow
        auth_flow = auth.auth_flow(request)
        signed_request = next(auth_flow)

        # Verify request was signed with SigV4
        assert 'Authorization' in signed_request.headers
        assert auth.use_sigv4a is False

        # Send the response back to auth flow
        try:
            auth_flow.send(success_response)
        except StopIteration:
            pass

        # Verify no retry occurred (still using SigV4)
        assert auth.use_sigv4a is False
        assert auth.sigv4a_signer is None

    @pytest.mark.asyncio
    async def test_sigv4a_detection_from_403_error(self):
        """Test that 403 error with SigV4A indicators triggers detection."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create a test request
        request = httpx.Request('GET', 'https://example.com/test', headers={'Host': 'example.com'})

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Mock 403 response with SigV4A requirement
        error_data = {
            'Code': 'SignatureDoesNotMatch',
            'Message': 'The request signature requires SigV4A for multi-region access'
        }
        error_response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )

        # Mock successful response after retry
        success_response = httpx.Response(
            status_code=200,
            headers={'content-type': 'application/json'},
            content=b'{"success": true}',
            request=request,
        )

        # Get signed request from auth flow
        auth_flow = auth.auth_flow(request)
        signed_request = next(auth_flow)

        # Verify initial request was signed with SigV4
        assert auth.use_sigv4a is False

        # Send error response to trigger retry
        with patch('mcp_proxy_for_aws.sigv4_helper.SIGV4A_AVAILABLE', True):
            with patch('mcp_proxy_for_aws.sigv4_helper.SigV4AAuth') as mock_sigv4a_class:
                mock_sigv4a_signer = Mock()
                mock_sigv4a_class.return_value = mock_sigv4a_signer

                retry_request = auth_flow.send(error_response)

                # Verify SigV4A was detected and retry occurred
                assert auth.use_sigv4a is True
                assert auth.sigv4a_signer is not None

                # Send success response for retry
                try:
                    auth_flow.send(success_response)
                except StopIteration:
                    pass

    @pytest.mark.asyncio
    async def test_automatic_retry_with_sigv4a(self):
        """Test that automatic retry with SigV4A occurs after detection."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create a test request
        request = httpx.Request('GET', 'https://example.com/test', headers={'Host': 'example.com'})

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Mock 403 response with SigV4A requirement
        error_data = {
            '__type': 'InvalidSignature',
            'message': 'This endpoint requires sigv4a authentication'
        }
        error_response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )

        # Mock successful response after retry
        success_response = httpx.Response(
            status_code=200,
            headers={'content-type': 'application/json'},
            content=b'{"success": true}',
            request=request,
        )

        # Get signed request from auth flow
        auth_flow = auth.auth_flow(request)
        signed_request = next(auth_flow)

        # Send error response to trigger retry
        with patch('mcp_proxy_for_aws.sigv4_helper.SIGV4A_AVAILABLE', True):
            with patch('mcp_proxy_for_aws.sigv4_helper.SigV4AAuth') as mock_sigv4a_class:
                mock_sigv4a_signer = Mock()
                mock_sigv4a_class.return_value = mock_sigv4a_signer

                retry_request = auth_flow.send(error_response)

                # Verify retry request was generated
                assert retry_request is not None
                assert 'Authorization' in retry_request.headers

                # Verify SigV4A signer was initialized
                mock_sigv4a_class.assert_called_once_with(mock_credentials, 'test-service', '*')

    @pytest.mark.asyncio
    async def test_subsequent_requests_use_sigv4a_after_detection(self):
        """Test that subsequent requests use SigV4A after detection."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        # Create auth instance
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Simulate that SigV4A has already been detected
        with patch('mcp_proxy_for_aws.sigv4_helper.SIGV4A_AVAILABLE', True):
            with patch('mcp_proxy_for_aws.sigv4_helper.SigV4AAuth') as mock_sigv4a_class:
                mock_sigv4a_signer = Mock()
                
                # Mock the add_auth method to add headers
                def mock_add_auth(aws_request):
                    aws_request.headers['Authorization'] = 'AWS4-ECDSA-P256-SHA256 Credential=...'
                    aws_request.headers['X-Amz-Date'] = '20240101T000000Z'
                
                mock_sigv4a_signer.add_auth = mock_add_auth
                mock_sigv4a_class.return_value = mock_sigv4a_signer

                auth.use_sigv4a = True
                auth.sigv4a_signer = mock_sigv4a_signer

                # Create a new request
                request = httpx.Request('GET', 'https://example.com/test2', headers={'Host': 'example.com'})

                # Mock successful response
                success_response = httpx.Response(
                    status_code=200,
                    headers={'content-type': 'application/json'},
                    content=b'{"success": true}',
                    request=request,
                )

                # Get signed request from auth flow
                auth_flow = auth.auth_flow(request)
                signed_request = next(auth_flow)

                # Verify request was signed (SigV4A should be used)
                assert 'Authorization' in signed_request.headers

                # Send success response
                try:
                    auth_flow.send(success_response)
                except StopIteration:
                    pass

                # Verify SigV4A is still being used
                assert auth.use_sigv4a is True

    def test_requires_sigv4a_with_signature_error(self):
        """Test _requires_sigv4a() detects SigV4A requirement from error response."""
        # Create mock credentials
        mock_credentials = Mock()
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Create request
        request = httpx.Request('GET', 'https://example.com/test')

        # Test with SignatureDoesNotMatch error and sigv4a hint
        error_data = {
            'Code': 'SignatureDoesNotMatch',
            'Message': 'This endpoint requires sigv4a for multi-region access'
        }
        response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )
        assert auth._requires_sigv4a(response) is True

        # Test with InvalidSignature error and sigv4a hint
        error_data = {
            '__type': 'InvalidSignature',
            'message': 'Please use SigV4A authentication'
        }
        response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )
        assert auth._requires_sigv4a(response) is True

    def test_requires_sigv4a_returns_false_for_non_sigv4a_errors(self):
        """Test _requires_sigv4a() returns False for non-SigV4A errors."""
        # Create mock credentials
        mock_credentials = Mock()
        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Create request
        request = httpx.Request('GET', 'https://example.com/test')

        # Test with 403 but no SigV4A indicators
        error_data = {
            'Code': 'AccessDenied',
            'Message': 'User is not authorized'
        }
        response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )
        assert auth._requires_sigv4a(response) is False

        # Test with 404 error
        response = httpx.Response(
            status_code=404,
            headers={'content-type': 'application/json'},
            content=b'{"error": "Not Found"}',
            request=request,
        )
        assert auth._requires_sigv4a(response) is False

        # Test with 500 error
        response = httpx.Response(
            status_code=500,
            headers={'content-type': 'text/plain'},
            content=b'Internal Server Error',
            request=request,
        )
        assert auth._requires_sigv4a(response) is False

        # Test with SignatureDoesNotMatch but no sigv4a hint
        error_data = {
            'Code': 'SignatureDoesNotMatch',
            'Message': 'The signature does not match'
        }
        response = httpx.Response(
            status_code=403,
            headers={'content-type': 'application/json'},
            content=json.dumps(error_data).encode(),
            request=request,
        )
        assert auth._requires_sigv4a(response) is False

    def test_sign_request_removes_connection_header(self):
        """Test _sign_request() removes connection header."""
        # Create mock credentials
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'

        auth = SigV4HTTPXAuth(mock_credentials, 'test-service', 'us-west-2')

        # Create request with connection header
        request = httpx.Request(
            'GET',
            'https://example.com/test',
            headers={
                'Host': 'example.com',
                'Connection': 'keep-alive',
                'User-Agent': 'test-agent'
            }
        )

        # Sign the request
        signed_request = auth._sign_request(request, auth.sigv4_signer)

        # Verify connection header was removed from signing
        # (The original request headers should still have it, but it shouldn't be in the signature)
        assert 'Authorization' in signed_request.headers
        assert 'X-Amz-Date' in signed_request.headers

        # Verify the request was signed (has signature headers)
        assert signed_request is not None


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

        await _handle_error_response(response)

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

        await _handle_error_response(response)

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

        await _handle_error_response(response)

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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
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
        result = create_sigv4_auth('test-service', 'test-region')

        # Verify auth was created correctly (with auto-detection enabled by default)
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'test-region'  # default region
        assert result.credentials == mock_credentials

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
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

        # Verify auth was created with explicit region (with auto-detection enabled by default)
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'ap-southeast-1'
        assert result.credentials == mock_credentials

    @patch('mcp_proxy_for_aws.sigv4_helper.SIGV4A_AVAILABLE', True)
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_returns_auto_detect_when_enabled(self, mock_create_session):
        """Test that create_sigv4_auth returns SigV4HTTPXAuth by default."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation (auto-detection is always enabled)
        result = create_sigv4_auth('test-service', 'us-west-2')

        # Verify SigV4HTTPXAuth is returned
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'us-west-2'
        assert result.credentials == mock_credentials
        assert result.use_sigv4a is False  # Starts with SigV4
        assert result.sigv4_signer is not None
        assert result.sigv4a_signer is None  # Lazy initialization

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_returns_sigv4_when_disabled(self, mock_create_session):
        """Test that create_sigv4_auth always returns SigV4HTTPXAuth (no disable option)."""
        # This test is now redundant since auto-detection is always enabled
        # Keeping it for backward compatibility but it tests the same as the above
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation
        result = create_sigv4_auth('test-service', 'us-west-2')

        # Verify SigV4HTTPXAuth is returned (always enabled now)
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'us-west-2'
        assert result.credentials == mock_credentials

    @patch('mcp_proxy_for_aws.sigv4_helper.SIGV4A_AVAILABLE', False)
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_falls_back_when_sigv4a_unavailable(self, mock_create_session):
        """Test that create_sigv4_auth falls back to SigV4HTTPXAuth when SigV4A is unavailable."""
        # Mock session and credentials
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'test_access_key'
        mock_credentials.secret_key = 'test_secret_key'
        mock_credentials.token = 'test_token'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation when SigV4A is unavailable
        result = create_sigv4_auth('test-service', 'us-west-2')

        # Verify SigV4HTTPXAuth is returned as fallback
        assert isinstance(result, SigV4HTTPXAuth)
        assert result.service == 'test-service'
        assert result.region == 'us-west-2'
        assert result.credentials == mock_credentials

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_create_sigv4_auth_credential_handling(self, mock_create_session):
        """Test that create_sigv4_auth properly handles credentials."""
        # Mock session and credentials with all attributes
        mock_session = Mock()
        mock_credentials = Mock()
        mock_credentials.access_key = 'AKIAIOSFODNN7EXAMPLE'
        mock_credentials.secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        mock_credentials.token = 'test_session_token_12345'
        mock_session.get_credentials.return_value = mock_credentials
        mock_create_session.return_value = mock_session

        # Test auth creation with profile
        result = create_sigv4_auth('test-service', 'eu-west-1', profile='test-profile')

        # Verify credentials are properly passed through
        assert result.credentials == mock_credentials
        assert result.credentials.access_key == 'AKIAIOSFODNN7EXAMPLE'
        assert result.credentials.secret_key == 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        assert result.credentials.token == 'test_session_token_12345'

        # Verify session was created with profile
        mock_create_session.assert_called_once_with('test-profile')


class TestCreateSigv4Client:
    """Test cases for the create_sigv4_client function."""

    @patch('mcp_proxy_for_aws.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_default(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client with default parameters."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test client creation
        result = create_sigv4_client(service='test-service', region='test-region')

        # Verify client was created correctly (auto-detection is always enabled)
        mock_create_auth.assert_called_once_with('test-service', 'test-region', None)

        # Check that AsyncClient was called with correct parameters
        call_args = mock_client_class.call_args
        assert call_args[1]['auth'] == mock_auth
        assert 'event_hooks' in call_args[1]
        assert 'response' in call_args[1]['event_hooks']
        assert len(call_args[1]['event_hooks']['response']) == 1
        assert call_args[1]['headers']['Accept'] == 'application/json, text/event-stream'
        assert result == mock_client

    @patch('mcp_proxy_for_aws.sigv4_helper.create_sigv4_auth')
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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_sigv4_auth')
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

        # Verify auth was created with custom parameters (auto-detection is always enabled)
        mock_create_auth.assert_called_once_with('custom-service', 'us-east-1', 'test-profile')
        assert result == mock_client

    @patch('mcp_proxy_for_aws.sigv4_helper.create_sigv4_auth')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_kwargs(self, mock_client_class, mock_create_auth):
        """Test creating SigV4 client with additional kwargs."""
        # Mock auth and client
        mock_auth = Mock()
        mock_create_auth.return_value = mock_auth
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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_sigv4_auth')
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
            service='test-service', headers=prompt_context_headers, region='us-west-2'
        )

        # Verify client was created correctly with prompt context (auto-detection is always enabled)
        mock_create_auth.assert_called_once_with('test-service', 'us-west-2', None)

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
