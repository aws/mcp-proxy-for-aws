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

import httpx2
import logging
from fastmcp import Client
from fastmcp.client.transports import ClientTransport
from fastmcp.server.providers.proxy import StatefulProxyClient
from mcp import MCPError
from mcp.types import InitializeRequest, JSONRPCError
from mcp_types.jsonrpc import jsonrpc_message_adapter
from typing_extensions import override


logger = logging.getLogger(__name__)


class AWSMCPProxyClient(StatefulProxyClient):
    """Proxy client that handles HTTP errors when connection fails.

    ``StatefulProxyClient`` is the base because this proxy bridges stdio to HTTP (SigV4), and
    the backend connection has to stay up for as long as the stdio pipe does. stdio has no
    equivalent of streamable-http's DELETE to end a session -- closing stdin terminates the
    subprocess -- so the connection is only torn down at program exit. That base releases each
    ``async with`` without disconnecting, which is exactly that lifecycle; overriding
    ``__aexit__`` to do nothing would also skip its nesting bookkeeping.

    https://modelcontextprotocol.io/specification/2024-11-05/basic/transports#stdio
    """

    def __init__(self, transport: ClientTransport, max_connect_retry=3, **kwargs):
        """Constructor of AWSMCPProxyClient."""
        super().__init__(transport, **kwargs)
        self._max_connect_retry = max_connect_retry

    @override
    async def _connect(self, retry=0):
        """Enter as normal && initialize only once."""
        logger.debug('Connecting %s', self)
        try:
            result = await super()._connect()
            logger.debug('Connected %s', self)
            return result
        except httpx2.HTTPStatusError as http_error:
            logger.exception('Connection failed')
            response = http_error.response
            try:
                body = await response.aread()
                jsonrpc_msg = jsonrpc_message_adapter.validate_json(body)
            except Exception as e:
                logger.debug('HTTP error is not a valid MCP message.', exc_info=e)
                raise http_error

            if isinstance(jsonrpc_msg, JSONRPCError):
                logger.debug('Converting HTTP error to MCP error', exc_info=http_error)
                # raising MCPError so that the sdk can handle the exception properly
                raise MCPError(
                    code=jsonrpc_msg.error.code,
                    message=jsonrpc_msg.error.message,
                    data=jsonrpc_msg.error.data,
                ) from http_error
            else:
                raise http_error
        except RuntimeError as e:
            if isinstance(e.__cause__, MCPError):
                raise e.__cause__

            if isinstance(e.__cause__, ValueError) and 'credentials' in str(e.__cause__).lower():
                from mcp.types import INTERNAL_ERROR

                raise MCPError(code=INTERNAL_ERROR, message=str(e.__cause__)) from e

            if retry > self._max_connect_retry:
                raise e

            try:
                logger.warning('encountered runtime error, try force disconnect.', exc_info=e)
                await self._disconnect(force=True)
            except (httpx2.TimeoutException, httpx2.HTTPStatusError):
                # _disconnect(force=True) resets the nesting counter then awaits the
                # session_task. That task may re-raise the exception that killed the
                # session (e.g. HTTPStatusError from a prior 401) or a TimeoutException.
                # Either way the error is safe to ignore: the counter is already 0 and
                # the retry below will establish a fresh session with refreshed credentials.
                logger.warning(
                    'Session cleanup failed during force disconnect, ignore and reconnect'
                )

            return await self._connect(retry + 1)


class AWSMCPProxyClientFactory:
    """Client factory that returns a connected client."""

    def __init__(self, transport: ClientTransport) -> None:
        """Initialize a client factory with transport."""
        self._transport = transport
        self._client: AWSMCPProxyClient | None = None
        self._initialize_request: InitializeRequest | None = None

    def set_init_params(self, initialize_request: InitializeRequest):
        """Set client init parameters."""
        self._initialize_request = initialize_request

    async def get_client(self) -> Client:
        """Get client."""
        if self._client is None:
            self._client = AWSMCPProxyClient(self._transport)

        return self._client

    async def __call__(self) -> Client:
        """Implement the callable factory interface."""
        return await self.get_client()

    async def disconnect(self):
        """Disconnect all the clients (no throw)."""
        try:
            if self._client:
                await self._client._disconnect(force=True)
        except Exception:
            logger.exception('Failed to disconnect client.')
