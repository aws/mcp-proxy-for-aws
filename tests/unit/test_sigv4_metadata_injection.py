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

"""Unit tests for sigv4_helper metadata injection hook."""

import httpx
import json
import pytest
from functools import partial
from mcp_proxy_for_aws.sigv4_helper import _inject_metadata_hook


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

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        # Call the hook
        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        # Verify metadata was injected
        modified_body = json.loads(stream_content.decode('utf-8'))
        assert '_meta' in modified_body['params']
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'
        assert modified_body['params']['_meta']['tracking_id'] == 'test-123'

        # Verify Content-Length was updated
        assert request.headers['content-length'] == str(len(stream_content))

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

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

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

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

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

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

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

        request = httpx.Request('POST', 'https://example.com/mcp', content=request_body)

        await _inject_metadata_hook(metadata, request)

        stream_content = await request.aread()

        modified_body = json.loads(stream_content.decode('utf-8'))

        # Other params should be preserved
        assert modified_body['params']['name'] == 'myTool'
        assert modified_body['params']['arguments'] == {'arg1': 'value1'}
        assert modified_body['params']['other_field'] == 'preserved'
        assert modified_body['params']['_meta']['AWS_REGION'] == 'us-west-2'
