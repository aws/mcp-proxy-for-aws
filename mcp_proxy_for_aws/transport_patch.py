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

"""Monkey-patch MCP SDK StreamableHTTPTransport to handle 401 auth errors.

The MCP SDK's transport architecture runs HTTP POST requests and response
waiting in separate anyio tasks:

    Task A (post_writer): Makes HTTP POST → gets 401 → raise_for_status() → Task A dies
    Task B (send_request): Waiting on response_stream → never gets a response → HANGS

Raising an exception in the httpx event hook (the previous approach) kills Task A,
but Task B still hangs indefinitely waiting for a response that will never come.

This patch intercepts 401 responses BEFORE raise_for_status() and converts them
to JSON-RPC error responses that flow through the normal MCP response channel
(read_stream_writer). This way Task B receives a proper error response and the
session doesn't hang.
"""

import logging

from mcp.client.streamable_http import StreamableHTTPTransport
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
)


logger = logging.getLogger(__name__)

# JSON-RPC error code for upstream authentication required
UPSTREAM_AUTH_ERROR_CODE = -32001


def apply_transport_401_patch() -> None:
    """Patch StreamableHTTPTransport._handle_post_request to handle 401.

    Wraps the original method to intercept HTTP 401 responses before
    raise_for_status() is called. Instead of crashing the transport task,
    a JSON-RPC error is sent through the normal response channel.
    """
    original_handle_post = StreamableHTTPTransport._handle_post_request

    async def patched_handle_post_request(self, ctx) -> None:
        """Wrapped _handle_post_request that intercepts 401 responses.

        Replicates the original's HTTP streaming setup but adds a 401 check
        between the existing status-code checks and raise_for_status().
        For non-401 cases, delegates to the original method's response handling.
        """
        headers = self._prepare_headers()
        message = ctx.session_message.message
        is_initialization = self._is_initialization_request(message)

        async with ctx.client.stream(
            "POST",
            self.url,
            json=message.model_dump(by_alias=True, mode="json", exclude_none=True),
            headers=headers,
        ) as response:
            # --- Begin: same status checks as original ---
            if response.status_code == 202:
                logger.debug("Received 202 Accepted")
                return

            if response.status_code == 404:
                if isinstance(message.root, JSONRPCRequest):
                    await self._send_session_terminated_error(
                        ctx.read_stream_writer,
                        message.root.id,
                    )
                return

            # --- 401 interception (the whole point of the patch) ---
            if response.status_code == 401:
                www_auth = response.headers.get("www-authenticate", "")
                logger.warning(
                    "Transport intercepted HTTP 401. WWW-Authenticate: %s",
                    www_auth,
                )

                # Extract request ID so the MCP session can match the error
                # to the pending request.
                request_id = None
                if isinstance(message.root, JSONRPCRequest):
                    request_id = message.root.id

                if request_id is not None:
                    jsonrpc_error = JSONRPCError(
                        jsonrpc="2.0",
                        id=request_id,
                        error=ErrorData(
                            code=UPSTREAM_AUTH_ERROR_CODE,
                            message=(
                                f"Authentication required (HTTP 401). "
                                f"WWW-Authenticate: {www_auth}"
                            ),
                            data={
                                "status_code": 401,
                                "www_authenticate": www_auth,
                            },
                        ),
                    )
                    session_message = SessionMessage(JSONRPCMessage(jsonrpc_error))
                    await ctx.read_stream_writer.send(session_message)
                else:
                    # Notification (no request ID) — just log, nothing to respond to.
                    logger.warning(
                        "HTTP 401 on a notification (no request ID); dropping."
                    )
                return  # Skip raise_for_status()

            # --- Non-401: fall through to original behaviour ---
            response.raise_for_status()
            if is_initialization:
                self._maybe_extract_session_id_from_response(response)

            if isinstance(message.root, JSONRPCRequest):
                content_type = response.headers.get("content-type", "").lower()
                if content_type.startswith("application/json"):
                    await self._handle_json_response(
                        response, ctx.read_stream_writer, is_initialization
                    )
                elif content_type.startswith("text/event-stream"):
                    await self._handle_sse_response(response, ctx, is_initialization)
                else:
                    await self._handle_unexpected_content_type(
                        content_type, ctx.read_stream_writer
                    )

    StreamableHTTPTransport._handle_post_request = patched_handle_post_request
    logger.info("Applied transport 401 patch to StreamableHTTPTransport")
