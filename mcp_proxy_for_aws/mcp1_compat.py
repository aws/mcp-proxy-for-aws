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

"""Non-2xx handling that mcp 1.x lacks. Delete this module after the move to mcp 2.x.

mcp 1.x calls ``raise_for_status()`` on a POST reply from inside the task it spawned for that
request (``mcp/client/streamable_http.py``), so a non-2xx tears the transport down instead of
answering the request. The caller stays parked in ``BaseSession.send_request``, which waits
without a timeout by default, and a session held on a background event loop, the shape agent
frameworks use, never recovers: the cancellation that should close the read stream also aborts
the receive loop before it can hand pending requests their error.

mcp 2.x answers the request id itself (``if response.status_code >= 400`` in the same file), so
this module is only needed while the dependency chain caps mcp below 2.0: today
``fastmcp>=3.2,<3.5`` -> ``fastmcp-slim`` -> ``mcp<2.0``. There is no fastmcp 3.5, so mcp 2.x
arrives with fastmcp 4.0. Delete this module, ``tests/unit/test_mcp1_compat.py``, and the hook
registration in ``client.py`` on that upgrade; none of the three survive it quietly, because
2.x turns ``JSONRPCMessage`` into a union alias that cannot be constructed.

Only the library path uses this. The proxy path needs to keep seeing ``httpx.HTTPStatusError``,
which both ``ToolErrorMiddleware`` and ``AWSMCPProxyClient._connect`` inspect.
"""

import httpx
import json
import logging
from mcp.types import ErrorData, JSONRPCError, JSONRPCMessage


logger = logging.getLogger(__name__)

_MAX_BODY_CHARS = 500


async def _translate_http_error_hook(response: httpx.Response) -> None:
    """Answer a failed POST with a JSON-RPC error keyed to the id the caller waits on.

    Rewriting the reply in place keeps the failure on the JSON-RPC channel: the transport reads
    a well formed error response, routes it to the pending request, and the caller gets an
    ``McpError`` naming the HTTP status while the session stays usable.
    """
    if not _is_unreported_failure(response):
        return

    message = _outgoing_jsonrpc_message(response.request)
    if message is None:
        return

    detail = await _read_failure_detail(response)

    request_id = message.get('id')
    if isinstance(request_id, (int, str)):
        _answer_pending_request(response, request_id, detail)
    else:
        _accept_failed_notification(response, message.get('method'), detail)


def _is_unreported_failure(response: httpx.Response) -> bool:
    """Report whether this is a failure the transport will not tell the caller about itself."""
    if response.request.method != 'POST':
        # GET (SSE) and DELETE (termination) failures are already contained by the transport.
        return False

    if response.status_code < 400:
        # 3xx is left alone: the default client follows redirects, and this hook runs first.
        return False

    # The transport reports a dropped session itself.
    return response.status_code != 404


def _outgoing_jsonrpc_message(request: httpx.Request) -> dict | None:
    """Parse the JSON-RPC message a request carries, or None if it does not look like one."""
    try:
        message = json.loads(request.content)
    except Exception as e:
        logger.debug('Request body is not JSON: %s', e)
        return None

    if isinstance(message, dict) and 'jsonrpc' in message:
        return message

    logger.debug('Request body is not a single JSON-RPC message')
    return None


async def _read_failure_detail(response: httpx.Response) -> str:
    """Read what the endpoint said about the failure, capped at a length safe to pass on."""
    try:
        body = await response.aread()
    except Exception as e:
        logger.debug('Could not read body of HTTP %d response: %s', response.status_code, e)
        return ''

    detail = body.decode('utf-8', errors='replace').strip()
    if len(detail) > _MAX_BODY_CHARS:
        return f'{detail[:_MAX_BODY_CHARS]}... (truncated)'
    return detail


def _answer_pending_request(response: httpx.Response, request_id: int | str, detail: str) -> None:
    """Turn the reply into the JSON-RPC error response the waiting request needs."""
    text = f'HTTP {response.status_code} {response.reason_phrase} from {response.url}'
    if detail:
        text = f'{text}: {detail}'

    logger.warning('%s. Reporting it to the caller as a JSON-RPC error.', text)

    error = JSONRPCError(
        jsonrpc='2.0', id=request_id, error=ErrorData(code=response.status_code, message=text)
    )

    response._content = (
        JSONRPCMessage(error).model_dump_json(by_alias=True, exclude_none=True).encode()
    )
    response.status_code = 200
    response.headers['content-type'] = 'application/json'


def _accept_failed_notification(response: httpx.Response, method: str | None, detail: str) -> None:
    """Report a failed notification as accepted, since nothing is waiting on a reply.

    The alternative is raise_for_status taking the whole transport down over a message that
    has no response.
    """
    logger.warning('HTTP %d for notification %r: %s', response.status_code, method, detail)
    response.status_code = 202
