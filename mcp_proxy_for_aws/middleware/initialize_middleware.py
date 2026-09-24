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

import logging
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp_proxy_for_aws.context import set_client_info
from mcp_proxy_for_aws.proxy import AWSMCPProxyClientFactory
from typing_extensions import override


logger = logging.getLogger(__name__)


class InitializeMiddleware(Middleware):
    """Intercept MCP initialize request and initialize the proxy client.

    Two entry points, one per protocol era:

    ``on_initialize`` handles the handshake eras (through ``2025-11-25``), where the client
    sends an ``initialize`` request carrying its identity. Every MCP client shipping today
    negotiates one of these, so this is the path that normally runs.

    ``on_request`` handles the ``2026-07-28`` era, where there is no handshake at all -- the
    protocol is sessionless, so ``on_initialize`` never fires and fastmcp documents it as
    such. Without a fallback the backend would stay unconnected until the first tool call, and
    a misconfigured endpoint would surface as a confusing mid-call failure rather than at
    connect time. The fallback restores the eager connect; it cannot restore the client
    identity, because the sessionless protocol does not carry ``clientInfo`` on any request.
    """

    def __init__(self, client_factory: AWSMCPProxyClientFactory) -> None:
        """Create a middleware with client factory."""
        super().__init__()
        self._client_factory = client_factory
        self._backend_connected = False

    @staticmethod
    def _backend_instructions(client) -> str | None:
        """Return the backend server's instructions, if it sent any.

        Reads ``Client.instructions`` rather than ``Client.initialize_result.instructions``:
        the latter is ``None`` whenever the backend connection negotiated the sessionless era,
        because there is no InitializeResult to hold it. ``Client.instructions`` is fastmcp 4's
        era-neutral accessor for the same value.
        """
        instructions = getattr(client, 'instructions', None)
        return instructions if isinstance(instructions, str) and instructions else None

    @staticmethod
    def _publish_instructions(context: MiddlewareContext, instructions: str) -> None:
        """Point the proxy's advertised instructions at the backend's.

        This is what the sessionless era reads: it has no handshake to answer, so it builds its
        ``server/discover`` reply from the server object at request time. Setting the attribute
        here is therefore enough on that era, and harmless on the handshake eras, where
        ``on_initialize`` additionally rewrites the already-built result.
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
            logger.info(
                'Captured client_info: name=%s, version=%s', client_info.name, client_info.version
            )
            client = await self._client_factory.get_client()
            # connect the http client, fail and don't succeed the stdio connect
            # if remote client cannot be connected
            client_name = client_info.name.lower()
            self._backend_connected = True
            if 'kiro cli' not in client_name and 'q dev cli' not in client_name:
                # q cli / kiro cli uses the rust SDK which does not handle json rpc error
                # properly during initialization.
                # https://github.com/modelcontextprotocol/rust-sdk/pull/569
                # if calling _connect below raise mcp error, the q cli will skip the message
                # and continue wait for a json rpc response message which will never come.
                # Luckily, q cli calls list tool immediately after being connected to a mcp server
                # the list_tool call will require the client to be connected again, so the mcp error
                # will be displayed in the q cli logs.
                await client._connect()

            # Report the backend's instructions rather than the proxy's own. Two routes are
            # needed because the eras read instructions at different moments: the handshake
            # eras snapshot them while `call_next` builds the result (rewritten below), the
            # sessionless era reads them off the server object (set in _publish_instructions).
            # Capabilities are no longer copied by hand; fastmcp 4's proxy negotiates them.
            instructions = self._backend_instructions(client)
            if instructions:
                self._publish_instructions(context, instructions)

            result = await call_next(context)
            if instructions and result is not None:
                result.instructions = instructions
            return result
        except Exception:
            logger.exception('Initialize failed in middleware.')
            raise

    @override
    async def on_request(self, context: MiddlewareContext, call_next: CallNext):
        """Connect the backend on the first request of a sessionless (2026-07-28) connection.

        On the handshake eras ``on_initialize`` has already run and set the flag, so this is a
        straight pass-through. On the sessionless era it stands in for the handshake that never
        happens, so the backend is reachable (or the failure is reported) before the first tool
        call rather than during it.
        """
        if not self._backend_connected:
            self._backend_connected = True
            logger.info(
                'No initialize handshake seen (sessionless protocol); '
                'connecting the backend on first request %s.',
                context.method,
            )
            client = await self._client_factory.get_client()
            await client._connect()
            instructions = self._backend_instructions(client)
            if instructions:
                self._publish_instructions(context, instructions)

        return await call_next(context)
