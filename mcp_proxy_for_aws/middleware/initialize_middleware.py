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
    """Connect the proxy client before the first tool call, and report the backend's identity.

    ``on_initialize`` runs when the client opens with a handshake, which is where the client
    identity comes from. Protocol version ``2026-07-28`` has no handshake, so ``on_request``
    connects the backend on the first request instead -- otherwise a bad endpoint would only
    surface mid-tool-call. That path has no client identity to capture.
    """

    def __init__(self, client_factory: AWSMCPProxyClientFactory) -> None:
        """Create a middleware with client factory."""
        super().__init__()
        self._client_factory = client_factory
        self._backend_connected = False

    @staticmethod
    def _backend_instructions(client) -> str | None:
        """Return the backend server's instructions, if it sent any.

        ``Client.initialize_result`` is ``None`` when the backend connection had no handshake,
        so read ``Client.instructions``, which holds the value either way.
        """
        instructions = getattr(client, 'instructions', None)
        return instructions if isinstance(instructions, str) and instructions else None

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

            # Report the backend's instructions rather than the proxy's own. A handshake
            # snapshots them while `call_next` builds the result, so that result is rewritten
            # below as well as the server object being set.
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
        """Connect the backend on the first request when the connection had no handshake.

        A pass-through once ``on_initialize`` has already connected.
        """
        if not self._backend_connected:
            self._backend_connected = True
            logger.info('No initialize handshake seen; connecting backend on %s.', context.method)
            client = await self._client_factory.get_client()
            await client._connect()
            instructions = self._backend_instructions(client)
            if instructions:
                self._publish_instructions(context, instructions)

        return await call_next(context)
