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

import asyncio
import logging
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp_proxy_for_aws.context import (
    get_client_capabilities,
    get_client_info,
    set_client_capabilities,
    set_client_info,
)
from mcp_proxy_for_aws.proxy import AWSMCPProxyClientFactory
from typing_extensions import override


logger = logging.getLogger(__name__)


class InitializeMiddleware(Middleware):
    """Connect the proxy client before the first tool call, and report the backend's identity.

    ``on_initialize`` runs only for a client that opens with a handshake. For one that opens
    without, ``on_request`` connects the backend on its first request instead -- otherwise a
    bad endpoint would only surface mid-tool-call -- and reads the client's identity off that
    request.
    """

    def __init__(self, client_factory: AWSMCPProxyClientFactory) -> None:
        """Create a middleware with client factory."""
        super().__init__()
        self._client_factory = client_factory
        self._backend_connected = False
        self._backend_capabilities: mt.ServerCapabilities | None = None
        self._connect_lock = asyncio.Lock()

    @staticmethod
    def _backend_instructions(client) -> str | None:
        """Return the backend server's instructions, if it sent any.

        ``Client.initialize_result`` is ``None`` when the backend connection had no handshake,
        so read ``Client.instructions``, which holds the value either way.
        """
        instructions = getattr(client, 'instructions', None)
        return instructions if isinstance(instructions, str) and instructions else None

    @staticmethod
    def _backend_server_capabilities(client) -> mt.ServerCapabilities | None:
        """Return what the backend server says it supports.

        ``Client.server_capabilities`` holds it whether or not the backend connection had a
        handshake.
        """
        capabilities = getattr(client, 'server_capabilities', None)
        return capabilities if isinstance(capabilities, mt.ServerCapabilities) else None

    def _advertise_backend_capabilities(self, result) -> None:
        """Replace the capabilities in a reply with the backend's.

        The proxy would otherwise advertise what its own handlers can do, which promises
        features the backend does not have and hides the extensions it does.
        """
        if self._backend_capabilities is None:
            return
        if isinstance(getattr(result, 'capabilities', None), mt.ServerCapabilities):
            result.capabilities = self._backend_capabilities

    @staticmethod
    def _capture_client_info(context: MiddlewareContext) -> None:
        """Record the client's identity when the request carried any.

        Without a handshake the client sends its identity alongside every request rather than
        once up front, and the SDK surfaces it on the session. Sending it is optional there, so
        a client that stays anonymous simply leaves the User-Agent suffix off.
        """
        fastmcp_ctx = context.fastmcp_context
        if fastmcp_ctx is None or fastmcp_ctx.request_context is None:
            return
        params = getattr(fastmcp_ctx.session, 'client_params', None)
        client_info = getattr(params, 'client_info', None)
        if not isinstance(client_info, mt.Implementation):
            return
        set_client_info(client_info)
        logger.info(
            'Captured client_info: name=%s, version=%s', client_info.name, client_info.version
        )

    @staticmethod
    def _capture_client_capabilities(context: MiddlewareContext) -> None:
        """Record the capabilities the client declared, when the request carried any.

        Without a handshake they ride along with each request. The backend connection is
        opened once, so those of the request that opens it are the ones it is given.
        """
        fastmcp_ctx = context.fastmcp_context
        if fastmcp_ctx is None or fastmcp_ctx.request_context is None:
            return
        capabilities = getattr(fastmcp_ctx.session, 'client_capabilities', None)
        if isinstance(capabilities, mt.ClientCapabilities):
            set_client_capabilities(capabilities)

    @staticmethod
    def _publish_instructions(context: MiddlewareContext, instructions: str) -> None:
        """Point the proxy's advertised instructions at the backend's.

        A handshake-free connection builds its reply from the server object at request time, so
        setting this is what it reads.
        """
        fastmcp_ctx = context.fastmcp_context
        if fastmcp_ctx is None:
            logger.debug('No fastmcp context available, skipping instructions forwarding.')
            return
        fastmcp_ctx.fastmcp.instructions = instructions

    @override
    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: CallNext[mt.InitializeRequest, mt.InitializeResult | None],
    ) -> mt.InitializeResult | None:
        try:
            logger.debug('Received initialize request %s.', context.message)
            self._client_factory.set_init_params(context.message)
            client_info = context.message.params.client_info
            set_client_info(client_info)
            set_client_capabilities(context.message.params.capabilities)
            logger.info(
                'Captured client_info: name=%s, version=%s', client_info.name, client_info.version
            )
            client = await self._client_factory.get_client()
            # connect the http client, fail and don't succeed the stdio connect
            # if remote client cannot be connected
            client_name = client_info.name.lower()
            if 'kiro cli' not in client_name and 'q dev cli' not in client_name:
                # q cli / kiro cli uses the rust SDK which does not handle json rpc error
                # properly during initialization.
                # https://github.com/modelcontextprotocol/rust-sdk/pull/569
                # if calling _connect below raise mcp error, the q cli will skip the message
                # and continue wait for a json rpc response message which will never come.
                # Luckily, q cli calls list tool immediately after being connected to a mcp server
                # that call reaches the backend again, so the failure is logged for them to find.
                await client._connect()
            self._backend_connected = True

            # Report the backend's instructions rather than the proxy's own. A handshake
            # snapshots them while `call_next` builds the result, so that result is rewritten
            # below as well as the server object being set.
            instructions = self._backend_instructions(client)
            if instructions:
                self._publish_instructions(context, instructions)

            self._backend_capabilities = self._backend_server_capabilities(client)

            result = await call_next(context)
            if instructions and result is not None:
                result.instructions = instructions
            self._advertise_backend_capabilities(result)
            return result
        except Exception:
            logger.exception('Initialize failed in middleware.')
            raise

    @override
    async def on_request(self, context: MiddlewareContext, call_next: CallNext):
        """Connect the backend on the first request when the connection had no handshake.

        A pass-through once ``on_initialize`` has already connected.
        """
        if get_client_info() is None:
            # Ahead of the connect below, so the backend's first signed request already
            # carries the client's User-Agent suffix.
            self._capture_client_info(context)

        if context.method == 'initialize':
            # This hook runs ahead of `on_initialize` in the chain, so connecting here would
            # pre-empt the handshake path and its per-client opt-outs. Leave it to that hook.
            return await call_next(context)

        if not self._backend_connected:
            # Ahead of the connect, so the backend's initialize carries them.
            if get_client_capabilities() is None:
                self._capture_client_capabilities(context)
            async with self._connect_lock:
                if not self._backend_connected:
                    await self._connect_backend(context)

        result = await call_next(context)
        if context.method == 'server/discover':
            self._advertise_backend_capabilities(result)
        return result

    async def _connect_backend(self, context: MiddlewareContext) -> None:
        """Connect the backend, marking it connected only once that has worked.

        A backend that cannot be reached therefore fails each request until it can, not just
        the first. ``server/discover`` is the exception: it is how a client works out which
        protocol era this server speaks, and one that errors is taken for a legacy server and
        sent a handshake it will be refused. So a failed connect is logged there and left to
        the next request, which raises the real error.
        """
        logger.info('No initialize handshake seen; connecting backend on %s.', context.method)
        try:
            client = await self._client_factory.get_client()
            await client._connect()
        except Exception:
            logger.exception('Backend connect failed on %s.', context.method)
            if context.method != 'server/discover':
                raise
            return

        self._backend_connected = True
        self._backend_capabilities = self._backend_server_capabilities(client)
        instructions = self._backend_instructions(client)
        if instructions:
            self._publish_instructions(context, instructions)
