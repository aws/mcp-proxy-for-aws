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
    SENSITIVE_HEADERS,
    CredentialProvider,
    SigV4HTTPXAuth,
    _sanitize_headers,
    _sign_request_hook_with_provider,
    create_aws_session,
    create_sigv4_client,
)
from unittest.mock import AsyncMock, Mock, patch


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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_default(self, mock_client_class, mock_create_session):
        """Test creating SigV4 client with default parameters."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_session = Mock()
        mock_create_session.return_value = mock_session

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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_headers(self, mock_client_class, mock_create_session):
        """Test creating SigV4 client with custom headers."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_session = Mock()
        mock_create_session.return_value = mock_session

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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_custom_service_and_region(
        self, mock_client_class, mock_create_session
    ):
        """Test creating SigV4 client with custom service and region."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock session creation
        mock_session = Mock()
        mock_session.get_credentials.return_value = Mock(access_key='test-key')
        mock_create_session.return_value = mock_session

        # Test client creation with custom parameters
        result = create_sigv4_client(
            service='custom-service', profile='test-profile', region='us-east-1'
        )

        # Verify session was created with profile
        mock_create_session.assert_called_once_with('test-profile')
        # Verify client was created
        assert result == mock_client

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_kwargs(self, mock_client_class, mock_create_session):
        """Test creating SigV4 client with additional kwargs."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_session = Mock()
        mock_create_session.return_value = mock_session

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

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @patch('httpx.AsyncClient')
    def test_create_sigv4_client_with_prompt_context(self, mock_client_class, mock_create_session):
        """Test creating SigV4 client when prompts exist in the system context.

        This test simulates the scenario where the sigv4_helper is used in a context
        where MCP prompts are present, ensuring the client is properly configured
        to handle requests that might include prompt-related content or headers.
        """
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_session = Mock()
        mock_create_session.return_value = mock_session

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


class TestSanitizeHeaders:
    """Test cases for the _sanitize_headers function."""

    def test_sanitize_headers_redacts_authorization(self):
        """Test that Authorization header is redacted."""
        headers = {
            'Authorization': 'AWS4-HMAC-SHA256 Credential=test-access-key/...',
            'Content-Type': 'application/json',
        }
        result = _sanitize_headers(headers)

        assert result['Authorization'] == '[REDACTED]'
        assert result['Content-Type'] == 'application/json'

    def test_sanitize_headers_redacts_security_token(self):
        """Test that x-amz-security-token header is redacted."""
        headers = {
            'x-amz-security-token': 'FwoGZXIvYXdzEBYaDK...',
            'Host': 'example.com',
        }
        result = _sanitize_headers(headers)

        assert result['x-amz-security-token'] == '[REDACTED]'
        assert result['Host'] == 'example.com'

    def test_sanitize_headers_redacts_amz_date(self):
        """Test that x-amz-date header is redacted."""
        headers = {
            'X-Amz-Date': '20260206T120000Z',
            'Accept': 'application/json',
        }
        result = _sanitize_headers(headers)

        assert result['X-Amz-Date'] == '[REDACTED]'
        assert result['Accept'] == 'application/json'

    def test_sanitize_headers_case_insensitive(self):
        """Test that header matching is case-insensitive."""
        headers = {
            'AUTHORIZATION': 'secret',
            'X-AMZ-SECURITY-TOKEN': 'secret',
            'x-amz-date': 'secret',
        }
        result = _sanitize_headers(headers)

        assert result['AUTHORIZATION'] == '[REDACTED]'
        assert result['X-AMZ-SECURITY-TOKEN'] == '[REDACTED]'
        assert result['x-amz-date'] == '[REDACTED]'

    def test_sanitize_headers_preserves_non_sensitive(self):
        """Test that non-sensitive headers are preserved."""
        headers = {
            'Content-Type': 'application/json',
            'Content-Length': '123',
            'Host': 'example.amazonaws.com',
            'User-Agent': 'test-client/1.0',
        }
        result = _sanitize_headers(headers)

        assert result == headers

    def test_sanitize_headers_empty_dict(self):
        """Test handling of empty headers dictionary."""
        result = _sanitize_headers({})
        assert result == {}

    def test_sensitive_headers_constant_is_frozen(self):
        """Test that SENSITIVE_HEADERS is immutable."""
        assert isinstance(SENSITIVE_HEADERS, frozenset)
        assert 'authorization' in SENSITIVE_HEADERS
        assert 'x-amz-security-token' in SENSITIVE_HEADERS
        assert 'x-amz-date' in SENSITIVE_HEADERS


class TestCredentialProvider:
    """Test cases for the CredentialProvider class."""

    def _make_session_mock(self, access_key='test-access-key'):
        """Helper to create a mock boto3 session with given access key."""
        mock_session = Mock()
        mock_frozen = Mock()
        mock_frozen.access_key = access_key
        mock_creds = Mock()
        mock_creds.get_frozen_credentials.return_value = mock_frozen
        mock_session.get_credentials.return_value = mock_creds
        return mock_session

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_initial_session_creation(self, mock_create_session):
        """Test that CredentialProvider creates a session on init."""
        mock_session = self._make_session_mock()
        mock_create_session.return_value = mock_session

        provider = CredentialProvider(profile='test-profile')

        mock_create_session.assert_called_once_with('test-profile')
        assert provider.get_session() is mock_session

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_returns_cached_session_when_files_unchanged(self, mock_create_session):
        """Test that get_session returns cached session when config files haven't changed."""
        mock_session = self._make_session_mock()
        mock_create_session.return_value = mock_session

        provider = CredentialProvider()
        result1 = provider.get_session()
        result2 = provider.get_session()

        assert result1 is result2
        # Only called once during __init__, not on subsequent get_session calls
        mock_create_session.assert_called_once()

    @patch('mcp_proxy_for_aws.sigv4_helper._get_file_mtimes')
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_creates_fresh_session_when_files_change(self, mock_create_session, mock_mtimes):
        """Test that get_session creates a fresh session when config files change."""
        session1 = self._make_session_mock(access_key='test-access-key-1')
        session2 = self._make_session_mock(access_key='test-access-key-1')
        mock_create_session.side_effect = [session1, session2]
        mock_mtimes.side_effect = [(1.0, 1.0), (2.0, 1.0)]

        provider = CredentialProvider()
        result = provider.get_session()

        # Fresh session used after file change, but same key = no identity change
        assert result is session2
        assert provider.consume_credentials_changed() is False

    @patch('mcp_proxy_for_aws.sigv4_helper._get_file_mtimes')
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_detects_credential_identity_change(self, mock_create_session, mock_mtimes):
        """Test that get_session detects when the access key changes."""
        session1 = self._make_session_mock(access_key='test-access-key-1')
        session2 = self._make_session_mock(access_key='test-access-key-2')
        mock_create_session.side_effect = [session1, session2]
        mock_mtimes.side_effect = [(1.0, 1.0), (2.0, 1.0)]

        provider = CredentialProvider()
        result = provider.get_session()

        assert result is session2
        assert provider.consume_credentials_changed() is True
        assert provider.consume_credentials_changed() is False

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_consume_credentials_changed_initially_false(self, mock_create_session):
        """Test that consume_credentials_changed returns False initially."""
        mock_create_session.return_value = self._make_session_mock()

        provider = CredentialProvider()
        assert provider.consume_credentials_changed() is False

    @patch('mcp_proxy_for_aws.sigv4_helper._get_file_mtimes')
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_falls_back_to_cached_session_on_error(self, mock_create_session, mock_mtimes):
        """Test that get_session falls back to cached session if fresh session fails."""
        original_session = self._make_session_mock()
        mock_create_session.side_effect = [original_session, ValueError('no creds')]
        mock_mtimes.side_effect = [(1.0, 1.0), (2.0, 1.0)]

        provider = CredentialProvider()
        result = provider.get_session()

        assert result is original_session
        assert provider.consume_credentials_changed() is False

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_no_credentials_returns_none_key(self, mock_create_session):
        """Test handling when session has no credentials."""
        mock_session = Mock()
        mock_session.get_credentials.return_value = None
        mock_create_session.return_value = mock_session

        provider = CredentialProvider()
        assert provider._access_key is None

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_uses_frozen_credentials(self, mock_create_session):
        """Test that access key is resolved via get_frozen_credentials."""
        mock_session = self._make_session_mock(access_key='test-access-key-1')
        mock_create_session.return_value = mock_session

        provider = CredentialProvider()

        mock_session.get_credentials().get_frozen_credentials.assert_called()
        assert provider._access_key == 'test-access-key-1'

    @patch('mcp_proxy_for_aws.sigv4_helper._get_file_mtimes')
    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    def test_multiple_identity_changes(self, mock_create_session, mock_mtimes):
        """Test detecting multiple sequential credential changes."""
        sessions = [
            self._make_session_mock(access_key='test-access-key-1'),
            self._make_session_mock(access_key='test-access-key-2'),
            self._make_session_mock(access_key='test-access-key-3'),
        ]
        mock_create_session.side_effect = sessions
        # init reads once, then each get_session reads once — alternate mtimes to trigger refresh
        mock_mtimes.side_effect = [
            (1.0, 1.0),  # init
            (2.0, 1.0),  # first get_session — changed
            (3.0, 1.0),  # second get_session — changed again
        ]

        provider = CredentialProvider()

        provider.get_session()
        assert provider.consume_credentials_changed() is True

        provider.get_session()
        assert provider.consume_credentials_changed() is True


class TestSignRequestHookWithProvider:
    """Test cases for _sign_request_hook_with_provider."""

    @pytest.mark.asyncio
    @patch('mcp_proxy_for_aws.sigv4_helper._sign_request_hook', new_callable=AsyncMock)
    async def test_delegates_to_sign_request_hook(self, mock_sign_hook):
        """Test that the provider hook calls get_session and delegates to _sign_request_hook."""
        mock_session = Mock()
        mock_provider = Mock(spec=CredentialProvider)
        mock_provider.get_session.return_value = mock_session
        mock_request = Mock(spec=httpx.Request)

        await _sign_request_hook_with_provider('us-east-1', 'bedrock', mock_provider, mock_request)

        mock_provider.get_session.assert_called_once()
        mock_sign_hook.assert_called_once_with('us-east-1', 'bedrock', mock_session, mock_request)
