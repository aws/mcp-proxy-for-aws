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
from fastmcp import Client
from fastmcp.client.transports import ClientTransport
from fastmcp.exceptions import NotFoundError
from fastmcp.server.proxy import ClientFactoryT
from fastmcp.server.proxy import FastMCPProxy as _FastMCPProxy
from fastmcp.server.proxy import ProxyClient as _ProxyClient
from fastmcp.server.proxy import ProxyToolManager as _ProxyToolManager
from fastmcp.tools import Tool
from mcp import McpError
from mcp.types import InitializeRequest, JSONRPCError, JSONRPCMessage
from typing import Any
from typing_extensions import override


logger = logging.getLogger(__name__)


class AWSProxyToolManager(_ProxyToolManager):
    """Customized proxy tool manager that better suites our needs."""

    def __init__(self, client_factory: ClientFactoryT, **kwargs: Any):
        """Initialize a proxy tool manager.

        Cached tools are set to None.
        """
        super().__init__(client_factory, **kwargs)
        self._cached_tools: dict[str, Tool] | None = None

    @override
    async def get_tool(self, key: str) -> Tool:
        """Return the tool from cached tools.

        This method is invoked when the client tries to call a tool.

            tool = self.get_tool(key)
            tool.invoke(...)

        The parent class implementation always make a mcp call to list the tools.
        Since the client already knows the name of the tools, list_tool is not necessary.
        We are wasting a network call just to get the tools which were already listed.

        In case the server supports notifications/tools/listChanged, the `get_tools` method
        will be called explicity , hence, we are not missing the change to the tool list.
        """
        if self._cached_tools is None:
            logger.debug('cached_tools not found, calling get_tools')
            self._cached_tools = await self.get_tools()
        if key in self._cached_tools:
            return self._cached_tools[key]
        raise NotFoundError(f'Tool {key!r} not found')

    @override
    async def get_tools(self) -> dict[str, Tool]:
        """Return list tools."""
        self._cached_tools = await super(AWSProxyToolManager, self).get_tools()
        return self._cached_tools


class AWSMCPProxy(_FastMCPProxy):
    """Customized MCP Proxy to better suite our needs."""

    def __init__(
        self,
        *,
        client_factory: ClientFactoryT | None = None,
        **kwargs,
    ):
        """Initialize a client."""
        super().__init__(client_factory=client_factory, **kwargs)
        self._tool_manager = AWSProxyToolManager(
            client_factory=self.client_factory,
            transformations=self._tool_manager.transformations,
        )


class AWSMCPProxyClient(_ProxyClient):
    """Proxy client that handles HTTP errors when connection fails."""

    def __init__(self, transport: ClientTransport, max_connect_retry=3, **kwargs):
        """Constructor of AutoRefreshProxyCilent."""
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
        except httpx.HTTPStatusError as http_error:
            logger.exception('Connection failed')
            response = http_error.response
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
                # TODO: investigate how timeout error is handled by fastmcp and httpx
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
