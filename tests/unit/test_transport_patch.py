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

"""Unit tests for transport_patch module."""

import httpx
import pytest
from contextlib import asynccontextmanager
from mcp.client.streamable_http import StreamableHTTPTransport
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
)
from mcp_proxy_for_aws.transport_patch import (
    UPSTREAM_AUTH_ERROR_CODE,
    apply_transport_401_patch,
)
from unittest.mock import AsyncMock, Mock, patch


class FakeStreamResponse:
    """Fake streaming response for testing.

    Simulates httpx's async streaming context manager returned by client.stream().
    """

    def __init__(self, status_code, headers=None, content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://example.com/mcp")
            response = httpx.Response(
                self.status_code, headers=self.headers, request=request
            )
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=request, response=response
            )


class FakeClient:
    """Fake httpx.AsyncClient that returns controllable streaming responses."""

    def __init__(self, response: FakeStreamResponse):
        self._response = response

    @asynccontextmanager
    async def stream(self, method, url, **kwargs):
        yield self._response


def make_request_context(
    client, message, read_stream_writer, session_id=None, metadata=None
):
    """Build a RequestContext for tests."""
    from mcp.client.streamable_http import RequestContext

    return RequestContext(
        client=client,
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
        session_id=session_id,
        session_message=SessionMessage(message),
        metadata=metadata,
        read_stream_writer=read_stream_writer,
        sse_read_timeout=300.0,
    )


def make_jsonrpc_request(method="tools/call", request_id=42):
    """Create a JSONRPCMessage wrapping a JSONRPCRequest."""
    return JSONRPCMessage(
        JSONRPCRequest(jsonrpc="2.0", id=request_id, method=method, params={})
    )


def make_jsonrpc_notification(method="notifications/initialized"):
    """Create a JSONRPCMessage wrapping a JSONRPCNotification."""
    return JSONRPCMessage(
        JSONRPCNotification(jsonrpc="2.0", method=method)
    )


class TestApplyTransportPatch:
    """Test that apply_transport_401_patch modifies StreamableHTTPTransport."""

    def test_patch_replaces_handle_post_request(self):
        """Test that the patch replaces _handle_post_request."""
        original = StreamableHTTPTransport._handle_post_request

        apply_transport_401_patch()

        assert StreamableHTTPTransport._handle_post_request is not original

    def test_patch_is_idempotent(self):
        """Test that calling apply twice doesn't break anything."""
        apply_transport_401_patch()
        first = StreamableHTTPTransport._handle_post_request

        apply_transport_401_patch()
        second = StreamableHTTPTransport._handle_post_request

        # Each call wraps, so they are different objects, but both should work
        assert callable(second)


class TestPatchedHandlePostRequest:
    """Test the patched _handle_post_request method behaviour."""

    @pytest.fixture(autouse=True)
    def apply_patch(self):
        """Ensure the transport patch is applied for every test."""
        apply_transport_401_patch()

    @pytest.mark.asyncio
    async def test_401_sends_jsonrpc_error_with_request_id(self):
        """Test that 401 on a request sends a JSON-RPC error through the read stream."""
        fake_response = FakeStreamResponse(
            401,
            headers={"www-authenticate": 'Bearer scope="aws.sigv4"'},
        )
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=99)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        await transport._handle_post_request(ctx)

        # Verify a SessionMessage was sent
        read_stream_writer.send.assert_called_once()
        sent = read_stream_writer.send.call_args[0][0]
        assert isinstance(sent, SessionMessage)

        # Verify the JSON-RPC error
        jsonrpc_msg = sent.message
        assert isinstance(jsonrpc_msg.root, JSONRPCError)
        assert jsonrpc_msg.root.id == 99
        assert jsonrpc_msg.root.error.code == UPSTREAM_AUTH_ERROR_CODE
        assert "401" in jsonrpc_msg.root.error.message
        assert "Bearer" in jsonrpc_msg.root.error.message
        assert jsonrpc_msg.root.error.data["status_code"] == 401
        assert jsonrpc_msg.root.error.data["www_authenticate"] == 'Bearer scope="aws.sigv4"'

    @pytest.mark.asyncio
    async def test_401_without_www_authenticate(self):
        """Test 401 handling when WWW-Authenticate header is missing."""
        fake_response = FakeStreamResponse(401, headers={})
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=7)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        await transport._handle_post_request(ctx)

        read_stream_writer.send.assert_called_once()
        sent = read_stream_writer.send.call_args[0][0]
        assert isinstance(sent.message.root, JSONRPCError)
        assert sent.message.root.error.data["www_authenticate"] == ""

    @pytest.mark.asyncio
    async def test_401_on_notification_does_not_send_error(self):
        """Test that 401 on a notification (no request ID) just logs."""
        fake_response = FakeStreamResponse(
            401,
            headers={"www-authenticate": "Bearer"},
        )
        client = FakeClient(fake_response)
        message = make_jsonrpc_notification()

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        await transport._handle_post_request(ctx)

        # No JSON-RPC error should be sent for notifications
        read_stream_writer.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_202_accepted_returns_early(self):
        """Test that 202 responses return without sending anything."""
        fake_response = FakeStreamResponse(202)
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=1)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        await transport._handle_post_request(ctx)

        read_stream_writer.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_404_sends_session_terminated_error(self):
        """Test that 404 responses trigger session terminated error."""
        fake_response = FakeStreamResponse(404)
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=5)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        await transport._handle_post_request(ctx)

        # Should have sent a session terminated error
        read_stream_writer.send.assert_called_once()
        sent = read_stream_writer.send.call_args[0][0]
        assert isinstance(sent, SessionMessage)
        assert isinstance(sent.message.root, JSONRPCError)
        assert sent.message.root.error.code == 32600  # Session terminated

    @pytest.mark.asyncio
    async def test_500_raises_http_status_error(self):
        """Test that non-401 errors still raise via raise_for_status()."""
        fake_response = FakeStreamResponse(500)
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=3)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")

        with pytest.raises(httpx.HTTPStatusError):
            await transport._handle_post_request(ctx)

    @pytest.mark.asyncio
    async def test_200_json_response_delegates_to_handler(self):
        """Test that 200 JSON responses are handled normally."""
        fake_response = FakeStreamResponse(
            200,
            headers={"content-type": "application/json"},
        )
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=10)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")

        # Mock _handle_json_response since we can't provide a real JSON body
        transport._handle_json_response = AsyncMock()

        await transport._handle_post_request(ctx)

        transport._handle_json_response.assert_called_once_with(
            fake_response, read_stream_writer, False
        )

    @pytest.mark.asyncio
    async def test_200_sse_response_delegates_to_handler(self):
        """Test that 200 SSE responses are handled normally."""
        fake_response = FakeStreamResponse(
            200,
            headers={"content-type": "text/event-stream"},
        )
        client = FakeClient(fake_response)
        message = make_jsonrpc_request(request_id=11)

        read_stream_writer = AsyncMock()
        ctx = make_request_context(client, message, read_stream_writer)

        transport = StreamableHTTPTransport("https://example.com/mcp")
        transport._handle_sse_response = AsyncMock()

        await transport._handle_post_request(ctx)

        transport._handle_sse_response.assert_called_once_with(
            fake_response, ctx, False
        )
