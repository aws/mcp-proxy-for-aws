import logging
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp_proxy_for_aws.proxy import AWSMCPProxyClientFactory
from typing_extensions import override


logger = logging.getLogger(__name__)


class InitializeMiddleware(Middleware):
    """Intecept MCP initialize request and initialize the proxy client."""

    def __init__(self, client_factory: AWSMCPProxyClientFactory) -> None:
        """Create a middleware with client factory."""
        super().__init__()
        self._client_factory = client_factory

    @override
    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: CallNext[mt.InitializeRequest, None],
    ) -> None:
        try:
            logger.debug('Received initialize request %s.', context.message)
            self._client_factory.set_init_params(context.message)
            client = await self._client_factory.get_client()
            # connect the http client, fail and don't succeed the stdio connect
            # if remote client cannot be connected
            client_name = context.message.params.clientInfo.name.lower()
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
            return await call_next(context)
        except Exception:
            logger.exception('Initialize failed in middleware.')
            raise
