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
            return await call_next(context)
        except Exception:
            logger.exception('Initialize failed in middleware.')
            raise
