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

"""Unit tests for hooks module."""

import httpx
import json
import pytest
from functools import partial
from mcp_proxy_for_aws.sigv4_helper import (
    _handle_error_response,
    _inject_metadata_hook,
    _sign_request_hook,
)
from unittest.mock import MagicMock, Mock, patch


def create_request_with_sigv4_headers(
    url: str, body: bytes, method: str = 'POST'
) -> httpx.Request:
    """Helper to create a request with required SigV4 headers for testing."""
    request = httpx.Request(method, url, content=body)
    # Add minimal SigV4 headers that the hook will try to delete and re-add
    request.headers['Content-Length'] = str(len(body))
    request.headers['x-amz-date'] = '20240101T000000Z'
    request.headers['x-amz-security-token'] = 'test-token'
    request.headers['Authorization'] = (
        'AWS4-HMAC-SHA256 Credential=test/20240101/us-west-2/execute-api/aws4_request'
    )
    return request


def create_mock_session():
    """Helper to create a mocked AWS session with credentials."""
    mock_session = MagicMock()
    mock_credentials = MagicMock()
    mock_credentials.access_key = 'test-access-key'
    mock_credentials.secret_key = 'test-secret-key'
    mock_credentials.token = 'test-token'
    mock_session.get_credentials.return_value = mock_credentials
    return mock_session


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

        # Verify response was read (content should be settled)
        assert response.is_stream_consumed

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

        # Verify response was read
        assert response.is_stream_consumed

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

        # Verify function completes without error for success responses
        assert response.status_code == 200

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

        # Verify it handled the read failure gracefully (no exception raised)
        # The aread() was attempted (would have been called)
        response.aread.assert_called_once()

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

        # Verify response was read despite invalid JSON
        assert response.is_stream_consumed


class TestMetadataInjectionHook:
    """Test cases for _inject_metadata_hook function."""

    @pytest.mark.asyncio
    async def test_hook_injects_metadata_into_jsonrpc_request(self):
        """Test that hook injects metadata into JSON-RPC request body."""
        metadata = {'AWS_REGION': 'us-west-2', 'tracking_id': 'test-123'}

        # Create request with JSON-RPC body
        request_body = json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'myTool'}}
        ).encode('utf-8')

        request = create_request_with_sigv4_headers('https://example.com/mcp', request_body)

        # Call the hook
        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        # Verify metadata was injected
        modified_body = json.loads(stream_content.decode('utf-8'))
        assert '_meta' in modified_body['params']
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'
        assert modified_body['params']['_meta']['tracking_id'] == 'test-123'

    @pytest.mark.asyncio
    async def test_hook_merges_with_existing_metadata(self):
        """Test that hook merges with existing _meta, existing takes precedence."""
        metadata = {'AWS_REGION': 'us-west-2', 'field1': 'injected'}

        request_body = json.dumps(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tools/call',
                'params': {
                    'name': 'myTool',
                    '_meta': {'field1': 'existing', 'field2': 'original'},
                },
            }
        ).encode('utf-8')

        request = create_request_with_sigv4_headers('https://example.com/mcp', request_body)

        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        modified_body = json.loads(stream_content.decode('utf-8'))

        # Existing metadata takes precedence
        assert modified_body['params']['_meta']['field1'] == 'existing'
        assert modified_body['params']['_meta']['field2'] == 'original'
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'

    @pytest.mark.asyncio
    async def test_hook_skips_non_jsonrpc_requests(self):
        """Test that hook doesn't modify non-JSON-RPC requests."""
        metadata = {'AWS_REGION': 'us-west-2'}

        request_body = json.dumps({'regular': 'request'}).encode('utf-8')
        original_body = request_body

        request = httpx.Request('POST', 'https://example.com/api', content=request_body)

        await _inject_metadata_hook(metadata, request)

        # Body should be unchanged
        assert request._content == original_body

    @pytest.mark.asyncio
    async def test_hook_handles_invalid_json_gracefully(self):
        """Test that hook handles invalid JSON without crashing."""
        metadata = {'AWS_REGION': 'us-west-2'}

        request_body = b'not valid json'
        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        # Should not raise exception
        await _inject_metadata_hook(metadata, request)

        # Body should be unchanged
        assert request._content == request_body

    @pytest.mark.asyncio
    async def test_hook_handles_empty_body(self):
        """Test that hook handles requests with no body."""
        metadata = {'AWS_REGION': 'us-west-2'}

        request = httpx.Request('GET', 'https://example.com/api')

        # Should not raise exception
        await _inject_metadata_hook(metadata, request)

    @pytest.mark.asyncio
    async def test_hook_handles_empty_metadata(self):
        """Test that hook works with empty metadata dict."""
        metadata = {}

        request_body = json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'myTool'}}
        ).encode('utf-8')

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        # Should not inject anything but shouldn't crash
        await _inject_metadata_hook(metadata, request)

    @pytest.mark.asyncio
    async def test_hook_with_partial_application(self):
        """Test that hook works correctly with functools.partial."""
        metadata = {'AWS_REGION': 'us-west-2', 'custom': 'value'}

        # Create curried function using partial
        curried_hook = partial(_inject_metadata_hook, metadata)

        request_body = json.dumps(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'myTool'}}
        ).encode('utf-8')

        request = create_request_with_sigv4_headers('https://example.com/mcp', request_body)

        # Call the curried function (only needs request parameter)
        await curried_hook(request)

        stream_content = await request.aread()

        modified_body = json.loads(stream_content.decode('utf-8'))
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'
        assert modified_body['params']['_meta']['custom'] == 'value'

    @pytest.mark.asyncio
    async def test_hook_handles_non_dict_meta(self):
        """Test that hook replaces non-dict _meta with dict."""
        metadata = {'AWS_REGION': 'us-west-2'}

        request_body = json.dumps(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tools/call',
                'params': {'name': 'myTool', '_meta': 'not a dict'},
            }
        ).encode('utf-8')

        request = create_request_with_sigv4_headers('https://example.com/mcp', request_body)

        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        modified_body = json.loads(stream_content.decode('utf-8'))

        # _meta should be replaced with dict
        assert isinstance(modified_body['params']['_meta'], dict)
        assert modified_body['params']['_meta'] == metadata

    @pytest.mark.asyncio
    async def test_hook_preserves_other_params(self):
        """Test that hook doesn't modify other params fields."""
        metadata = {'AWS_REGION': 'us-west-2'}

        request_body = json.dumps(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tools/call',
                'params': {
                    'name': 'myTool',
                    'arguments': {'arg1': 'value1'},
                    'other_field': 'preserved',
                },
            }
        ).encode('utf-8')

        request = create_request_with_sigv4_headers('https://example.com/mcp', request_body)

        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        modified_body = json.loads(stream_content.decode('utf-8'))

        # Other params should be preserved
        assert modified_body['params']['name'] == 'myTool'
        assert modified_body['params']['arguments'] == {'arg1': 'value1'}
        assert modified_body['params']['other_field'] == 'preserved'
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'


class TestSignRequestHook:
    """Test cases for sign_request_hook function."""

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @pytest.mark.asyncio
    async def test_sign_request_hook_signs_request(self, mock_create_session):
        """Test that sign_request_hook properly signs requests."""
        # Setup mocks
        mock_create_session.return_value = create_mock_session()

        region = 'us-east-1'
        service = 'bedrock-agentcore'
        profile = None

        # Create request without signature headers
        request_body = json.dumps({'test': 'data'}).encode('utf-8')
        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        # Call the hook
        await _sign_request_hook(region, service, profile, request)

        # Verify signature headers were added
        assert 'authorization' in request.headers
        assert 'x-amz-date' in request.headers
        assert 'x-amz-security-token' in request.headers
        assert request.headers['content-length'] == str(len(request_body))

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @pytest.mark.asyncio
    async def test_sign_request_hook_with_profile(self, mock_create_session):
        """Test that sign_request_hook uses profile when provided."""
        # Setup mocks
        mock_create_session.return_value = create_mock_session()

        region = 'us-west-2'
        service = 'execute-api'
        profile = 'test-profile'

        request_body = b'test content'
        request = httpx.Request('POST', 'https://example.com/api', content=request_body)

        # Call the hook
        await _sign_request_hook(region, service, profile, request)

        # Verify session was created with profile
        mock_create_session.assert_called_once_with(profile)

        # Verify request was signed
        assert 'authorization' in request.headers
        assert 'x-amz-date' in request.headers

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @pytest.mark.asyncio
    async def test_sign_request_hook_sets_content_length(self, mock_create_session):
        """Test that sign_request_hook sets Content-Length header."""
        # Setup mocks
        mock_create_session.return_value = create_mock_session()

        region = 'eu-west-1'
        service = 'lambda'
        profile = None

        # Create request
        request_body = b'test content with specific length'
        request = httpx.Request('POST', 'https://example.com/api', content=request_body)

        await _sign_request_hook(region, service, profile, request)

        # Verify Content-Length was set correctly
        assert request.headers['content-length'] == str(len(request_body))

    @patch('mcp_proxy_for_aws.sigv4_helper.create_aws_session')
    @pytest.mark.asyncio
    async def test_sign_request_hook_with_partial_application(self, mock_create_session):
        """Test that sign_request_hook works with functools.partial."""
        # Setup mocks
        mock_create_session.return_value = create_mock_session()

        region = 'ap-southeast-1'
        service = 'execute-api'
        profile = 'prod-profile'

        # Create curried function using partial
        curried_hook = partial(_sign_request_hook, region, service, profile)

        request_body = b'request data'
        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        # Call the curried function (only needs request parameter)
        await curried_hook(request)

        # Verify request was signed
        assert 'authorization' in request.headers
        assert 'x-amz-date' in request.headers
        mock_create_session.assert_called_once_with(profile)
