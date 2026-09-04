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

"""Unit tests for the mcp 1.x non-2xx workaround.

Delete this file together with `mcp_proxy_for_aws.mcp1_compat`. It uses mcp 1.x APIs that
2.x drops, so it stops importing on the upgrade rather than passing silently.
"""

import asyncio
import httpx
import json
import pytest
from botocore.credentials import Credentials
from mcp import ClientSession, McpError
from mcp.types import JSONRPCError, JSONRPCMessage
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client
from mcp_proxy_for_aws.mcp1_compat import _translate_http_error_hook
from mcp_proxy_for_aws.sigv4_helper import create_sigv4_client


ENDPOINT = 'https://mcp.example.com/mcp'
CREDENTIALS = Credentials('test_key', 'test_secret', 'test_token')

TOOLS_CALL = {
    'jsonrpc': '2.0',
    'id': 7,
    'method': 'tools/call',
    'params': {'name': 'type_text', 'arguments': {'text': 'a'}},
}
INITIALIZED_NOTIFICATION = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}


def test_proxy_path_does_not_carry_the_workaround():
    """Keep this off the proxy path, which needs to go on seeing httpx.HTTPStatusError.

    `ToolErrorMiddleware` and `AWSMCPProxyClient._connect` both inspect that exception, so
    answering the request here instead would replace their messages with a generic one.
    """
    proxy_client = create_sigv4_client(service='test-service', region='us-west-2')

    assert _translate_http_error_hook not in proxy_client.event_hooks['response']


def build_response(
    status_code: int,
    body: bytes = b'',
    request_body: dict | list | bytes = TOOLS_CALL,
    method: str = 'POST',
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a response as httpx hands it to a response hook."""
    content = (
        request_body if isinstance(request_body, bytes) else json.dumps(request_body).encode()
    )
    request = httpx.Request(method, ENDPOINT, content=content)
    return httpx.Response(status_code, content=body, headers=headers, request=request)


def parse_body(response: httpx.Response) -> JSONRPCError:
    """Read the response body back as the JSON-RPC error the transport will see."""
    message = JSONRPCMessage.model_validate_json(response.content).root
    assert isinstance(message, JSONRPCError)
    return message


async def test_failed_request_becomes_jsonrpc_error_for_the_pending_id():
    """A rejected tool call is answered on the JSON-RPC channel, keyed to the request id."""
    # 413 with an empty body and no content type is what a CloudFront WAF returns.
    response = build_response(413, b'')

    await _translate_http_error_hook(response)

    assert response.status_code == 200
    assert response.headers['content-type'] == 'application/json'
    error = parse_body(response)
    assert error.id == 7
    assert error.error.code == 413
    assert 'HTTP 413' in error.error.message
    assert ENDPOINT in error.error.message


async def test_response_body_is_quoted_in_the_error_message():
    """Whatever the endpoint said about the failure reaches the caller."""
    response = build_response(500, b'upstream blew up')

    await _translate_http_error_hook(response)

    assert 'upstream blew up' in parse_body(response).error.message


async def test_long_response_body_is_truncated():
    """A large error body cannot be pasted wholesale into the error message."""
    response = build_response(500, b'x' * 5000)

    await _translate_http_error_hook(response)

    message = parse_body(response).error.message
    assert '... (truncated)' in message
    assert len(message) < 1000


async def test_unreadable_body_still_produces_an_error():
    """A body that cannot be read must not stop the caller from being told the status."""
    response = build_response(502, b'')

    async def failing_aread():
        raise httpx.ReadError('connection reset while reading the error body')

    response.aread = failing_aread  # type: ignore[method-assign]

    await _translate_http_error_hook(response)

    assert parse_body(response).error.code == 502


async def test_failed_notification_is_reported_as_accepted():
    """Nothing waits on a notification, so the session is kept instead of torn down."""
    response = build_response(500, b'nope', request_body=INITIALIZED_NOTIFICATION)

    await _translate_http_error_hook(response)

    assert response.status_code == 202


@pytest.mark.parametrize(
    'kwargs',
    [
        pytest.param({'status_code': 200, 'body': b'{}'}, id='success'),
        pytest.param({'status_code': 202}, id='accepted'),
        pytest.param(
            {'status_code': 307, 'headers': {'location': 'https://elsewhere.example.com/mcp'}},
            id='redirect-left-to-httpx',
        ),
        pytest.param({'status_code': 404}, id='session-terminated'),
        pytest.param({'status_code': 405, 'method': 'GET'}, id='get-sse-not-supported'),
        pytest.param({'status_code': 405, 'method': 'DELETE'}, id='delete-not-supported'),
        pytest.param({'status_code': 500, 'request_body': b'not json'}, id='unparseable-request'),
        pytest.param({'status_code': 500, 'request_body': [TOOLS_CALL]}, id='batched-request'),
    ],
)
async def test_responses_left_untouched(kwargs):
    """Cases the transport already handles are passed through unchanged."""
    response = build_response(**kwargs)
    original_status = response.status_code
    original_body = response.content

    await _translate_http_error_hook(response)

    assert response.status_code == original_status
    assert response.content == original_body


def mock_client_factory(handler):
    """Build an httpx client factory that serves responses from handler."""

    def factory(headers=None, timeout=None, auth=None, **kwargs):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), headers=headers, timeout=timeout, auth=auth
        )

    return factory


def mcp_endpoint(oversize_limit: int):
    """Serve MCP over HTTP, rejecting oversize tool calls the way a WAF does."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != 'POST':
            # The server supports neither the GET stream nor session termination.
            return httpx.Response(405)

        message = json.loads(request.content)
        method = message['method']
        calls.append(method)

        if method == 'initialize':
            return httpx.Response(
                200,
                json={
                    'jsonrpc': '2.0',
                    'id': message['id'],
                    'result': {
                        'protocolVersion': '2025-06-18',
                        'capabilities': {'tools': {}},
                        'serverInfo': {'name': 'test', 'version': '1.0.0'},
                    },
                },
            )
        if method.startswith('notifications/'):
            return httpx.Response(202)
        if method == 'tools/list':
            return httpx.Response(
                200,
                json={
                    'jsonrpc': '2.0',
                    'id': message['id'],
                    'result': {
                        'tools': [
                            {
                                'name': 'type_text',
                                'inputSchema': {
                                    'type': 'object',
                                    'properties': {'text': {'type': 'string'}},
                                },
                            }
                        ]
                    },
                },
            )
        if len(request.content) > oversize_limit:
            return httpx.Response(413)
        return httpx.Response(
            200,
            json={
                'jsonrpc': '2.0',
                'id': message['id'],
                'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
            },
        )

    return handler, calls


async def test_rejected_tool_call_raises_and_leaves_the_session_usable():
    """The caller is told about the 413 and can keep using the session afterwards."""
    handler, calls = mcp_endpoint(oversize_limit=2048)

    async def drive():
        client = aws_iam_streamablehttp_client(
            endpoint=ENDPOINT,
            aws_service='bedrock-agentcore',
            aws_region='us-west-2',
            credentials=CREDENTIALS,
            httpx_client_factory=mock_client_factory(handler),
        )
        async with client as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                with pytest.raises(McpError) as rejected:
                    await session.call_tool('type_text', {'text': 'a' * 20000})

                # The transport survived, so the next call still goes through.
                result = await session.call_tool('type_text', {'text': 'a'})
                return rejected.value, result

    # Bounded so a regression fails the test instead of hanging the suite.
    error, result = await asyncio.wait_for(drive(), timeout=30)

    assert error.error.code == 413
    assert 'HTTP 413' in str(error)
    assert result.content[0].text == 'ok'  # type: ignore[union-attr]
    assert calls[:4] == ['initialize', 'notifications/initialized', 'tools/call', 'tools/call']
