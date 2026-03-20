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

import httpx
import logging
from collections.abc import Sequence
from fastmcp import Client
from fastmcp.client.transports import ClientTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.context import Context
from fastmcp.server.providers.proxy import (
    ClientFactoryT,
    FastMCPProxy as _FastMCPProxy,
    ProxyClient as _ProxyClient,
    ProxyProvider as _ProxyProvider,
    ProxyTool as _ProxyTool,
)
from fastmcp.tools import Tool
from fastmcp.tools.tool import ToolResult
from mcp import McpError
from mcp.types import ErrorData, InitializeRequest, JSONRPCError, JSONRPCMessage
from mcp_proxy_for_aws.sigv4_helper import UpstreamAuthenticationError
from typing import Any
from typing_extensions import override


logger = logging.getLogger(__name__)


class AWSProxyTool(_ProxyTool):
    """ProxyTool that converts upstream 401 errors to ToolError.

    Catches authentication failures from the upstream server and surfaces
    them as ToolError with WWW-Authenticate details, preventing 401s from
    crashing the MCP SDK transport task.
    """

    @override
    async def run(
        self,
        arguments: dict[str, Any],
        context: Context | None = None,
    ) -> ToolResult:
        """Execute the tool, converting upstream 401 errors to ToolError."""
        try:
            return await super().run(arguments, context)
        except UpstreamAuthenticationError as auth_error:
            logger.warning('Upstream auth required for tool call: %s', auth_error)
            raise ToolError(
                f'Authentication required (HTTP 401). '
                f'WWW-Authenticate: {auth_error.www_authenticate}'
            ) from auth_error
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                www_auth = e.response.headers.get('www-authenticate', '')
                raise ToolError(
                    f'Authentication required (HTTP 401). WWW-Authenticate: {www_auth}'
                ) from e
            raise
        except McpError as e:
            if (
                e.error.data
                and isinstance(e.error.data, dict)
                and e.error.data.get('status_code') == 401
            ):
                www_auth = e.error.data.get('www_authenticate', '')
                raise ToolError(
                    f'Authentication required (HTTP 401). WWW-Authenticate: {www_auth}'
                ) from e
            raise
        except ToolError:
            raise
        except Exception as e:
            # Check if the root cause was an auth error wrapped by anyio or MCP session
            cause = e.__cause__ or e.__context__
            while cause:
                if isinstance(cause, UpstreamAuthenticationError):
                    raise ToolError(
                        f'Authentication required (HTTP 401). '
                        f'WWW-Authenticate: {cause.www_authenticate}'
                    ) from cause
                cause = getattr(cause, '__cause__', None) or getattr(cause, '__context__', None)
            raise


class AWSProxyProvider(_ProxyProvider):
    """ProxyProvider with tool caching and custom ProxyTool type.

    Caches tool listings so that subsequent get_tool lookups (during tool
    invocation) don't redundantly re-list from the remote server.
    Uses AWSProxyTool instead of ProxyTool for 401 error handling.
    """

    def __init__(self, client_factory: ClientFactoryT):
        """Initialize the provider."""
        super().__init__(client_factory)
        self._cached_tools: Sequence[Tool] | None = None

    @override
    async def _list_tools(self) -> Sequence[Tool]:
        """List tools from the remote server, using AWSProxyTool for 401 handling."""
        from mcp.shared.exceptions import McpError
        from mcp.types import METHOD_NOT_FOUND

        try:
            client = await self._get_client()
            async with client:
                mcp_tools = await client.list_tools()
                tools = [
                    AWSProxyTool.from_mcp_tool(self.client_factory, t) for t in mcp_tools
                ]
                self._cached_tools = tools
                return tools
        except McpError as e:
            if e.error.code == METHOD_NOT_FOUND:
                return []
            raise

    def invalidate_cache(self) -> None:
        """Invalidate the cached tools, forcing a re-list on next access."""
        self._cached_tools = None


class AWSMCPProxy(_FastMCPProxy):
    """Customized MCP Proxy using AWSProxyProvider for 401 handling and caching."""

    def __init__(
        self,
        *,
        client_factory: ClientFactoryT | None = None,
        **kwargs,
    ):
        """Initialize the proxy with AWSProxyProvider instead of the default ProxyProvider."""
        # Call FastMCP.__init__ directly (skip _FastMCPProxy which adds a default ProxyProvider)
        from fastmcp.server.server import FastMCP
        FastMCP.__init__(self, **kwargs)
        self.client_factory = client_factory
        provider = AWSProxyProvider(client_factory)
        self.add_provider(provider)


class AWSMCPProxyClient(_ProxyClient):
    """Proxy client that handles HTTP errors when connection fails."""

    def __init__(self, transport: ClientTransport, max_connect_retry=3, **kwargs):
        """Constructor of AWSMCPProxyClient."""
        super().__init__(transport, **kwargs)
        self._max_connect_retry = max_connect_retry

    @override
    async def _connect(self, retry=0):
        """Enter as normal && initialize only once."""
        logger.debug('Connecting %s', self)
        try:
            result = await super(AWSMCPProxyClient, self)._connect()
            logger.debug('Connected %s', self)
            return result
        except UpstreamAuthenticationError as auth_error:
            logger.warning('Upstream auth required during connect: %s', auth_error)
            raise McpError(
                error=ErrorData(
                    code=-32001,
                    message='Authentication required',
                    data={
                        'status_code': auth_error.status_code,
                        'www_authenticate': auth_error.www_authenticate,
                    },
                )
            ) from auth_error
        except httpx.HTTPStatusError as http_error:
            logger.exception('Connection failed')
            response = http_error.response

            if response.status_code == 401:
                www_auth = response.headers.get('www-authenticate', '')
                logger.warning('Upstream returned 401. WWW-Authenticate: %s', www_auth)
                raise McpError(
                    error=ErrorData(
                        code=-32001,
                        message='Authentication required',
                        data={'status_code': 401, 'www_authenticate': www_auth},
                    )
                ) from http_error

            try:
                body = await response.aread()
                jsonrpc_msg = JSONRPCMessage.model_validate_json(body).root
            except Exception as e:
                logger.debug('HTTP error is not a valid MCP message.', exc_info=e)
                raise http_error

            if isinstance(jsonrpc_msg, JSONRPCError):
                logger.debug('Converting HTTP error to MCP error', exc_info=http_error)
                # raising McpError so that the sdk can handle the exception properly
                raise McpError(error=jsonrpc_msg.error) from http_error
            else:
                raise http_error
        except RuntimeError as e:
            if isinstance(e.__cause__, McpError):
                raise e.__cause__

            if retry > self._max_connect_retry:
                raise e

            try:
                logger.warning('encountered runtime error, try force disconnect.', exc_info=e)
                await self._disconnect(force=True)
            except httpx.TimeoutException:
                # _disconnect awaits on the session_task,
                # which raises the timeout error that caused the client session to be terminated.
                # the error is ignored as long as the counter is force set to 0.
                logger.exception(
                    'Session was terminated due to timeout error, ignore and reconnect'
                )

            return await self._connect(retry + 1)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """The MCP Proxy for AWS project is a proxy from stdio to http (sigv4).

        We want the client to remain connected until the stdio connection is closed.

        https://modelcontextprotocol.io/specification/2024-11-05/basic/transports#stdio

            1. close stdin
            2. terminate subprocess

        There is no equivalent of the streamble-http DELETE concept in stdio to terminate a session.
        Hence the connection will be terminated only at program exit.
        """
        pass


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
