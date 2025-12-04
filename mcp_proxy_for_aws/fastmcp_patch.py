import fastmcp.server.low_level as low_level_module
import mcp.types
from functools import wraps
from mcp import McpError
from mcp.server.stdio import stdio_server as stdio_server
from mcp.shared.session import RequestResponder


original_receive_request = low_level_module.MiddlewareServerSession._received_request


@wraps(original_receive_request)
async def _received_request(
    self,
    responder: RequestResponder[mcp.types.ClientRequest, mcp.types.ServerResult],
):
    """Monkey patch fastmcp so that the initialize error from the middleware can be send back to the client.

    https://github.com/jlowin/fastmcp/pull/2531
    """
    if isinstance(responder.request.root, mcp.types.InitializeRequest):
        try:
            return await original_receive_request(self, responder)
        except McpError as e:
            if not responder._completed:
                with responder:
                    return await responder.respond(e.error)

            raise e
    else:
        return await original_receive_request(self, responder)


low_level_module.MiddlewareServerSession._received_request = _received_request
