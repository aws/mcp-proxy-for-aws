import boto3
import fastmcp
import logging
from fastmcp.client import StdioTransport
from fastmcp.client.elicitation import ElicitResult


logger = logging.getLogger(__name__)


def build_mcp_client(endpoint: str, region_name: str) -> fastmcp.Client:
    """Create a MCP Client using the mcp-proxy-for-aws against a remote MCP Server."""
    return fastmcp.Client(
        StdioTransport(
            **_build_mcp_config(
                endpoint=endpoint,
                region_name=region_name,
            )
        ),
        elicitation_handler=_basic_elicitation_handler,
        timeout=30.0,  # seconds
    )


async def _basic_elicitation_handler(message: str, response_type: type, params, context):
    logger.info(f'Server asks: {message} with response_type {response_type}')

    # Usually the Handler would expect an user Input to control flow via Accept, Decline, Cancel
    # But in this Integ test we only care that an Elicitation request went through the handler
    # and responded correctly.
    # As such, we are explicitly hardcoding the response based on the name of the ResponseType object

    if 'Accept' in response_type.__name__:
        return response_type(value='Elicitation success')

    if 'Decline' in response_type.__name__:
        return ElicitResult(action='decline')

    raise RuntimeError(f'Unknown Response-type, rather failing - {response_type}')


def _build_mcp_config(endpoint: str, region_name: str):
    credentials = boto3.Session().get_credentials()

    environment_variables = {
        'AWS_REGION': region_name,
        'AWS_ACCESS_KEY_ID': credentials.access_key,
        'AWS_SECRET_ACCESS_KEY': credentials.secret_key,
        'AWS_SESSION_TOKEN': credentials.token,
    }

    return {
        'command': 'mcp-proxy-for-aws',
        'args': [
            endpoint,
            '--log-level',
            'DEBUG',
            '--region',
            region_name,
        ],
        'env': environment_variables,
    }
