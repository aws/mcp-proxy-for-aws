import boto3
import fastmcp
import logging
from fastmcp.client import StdioTransport
from fastmcp.client.elicitation import ElicitResult
from typing import Dict, Optional


logger = logging.getLogger(__name__)


def build_mcp_client(
    endpoint: str, region_name: str, metadata: Optional[Dict[str, str]] = None
) -> fastmcp.Client:
    """Create a MCP Client with custom metadata.

    Args:
        endpoint: The MCP server endpoint URL
        region_name: AWS region name
        metadata: Optional custom metadata to pass via --metadata flag

    Returns:
        fastmcp.Client configured to use mcp-proxy-for-aws with custom metadata
    """
    return fastmcp.Client(
        StdioTransport(
            **_build_mcp_config(endpoint=endpoint, region_name=region_name, metadata=metadata)
        ),
        elicitation_handler=_basic_elicitation_handler,
        timeout=30.0,  # seconds
    )


async def _basic_elicitation_handler(message: str, response_type: type, params, context):
    logger.info('Server asks: %s with response_type %s', message, response_type)

    # Usually the Handler would expect an user Input to control flow via Accept, Decline, Cancel
    # But in this Integ test we only care that an Elicitation request went through the handler
    # and responded correctly.
    # As such, we are explicitly hardcoding the response based on the name of the ResponseType object

    if 'Accept' in response_type.__name__:
        return response_type(value='Elicitation success')

    if 'Decline' in response_type.__name__:
        return ElicitResult(action='decline')

    raise RuntimeError(f'Unknown Response-type, rather failing - {response_type}')


def _build_mcp_config(endpoint: str, region_name: str, metadata: Optional[Dict[str, str]] = None):
    credentials = boto3.Session().get_credentials()

    environment_variables = {
        'AWS_REGION': region_name,
        'AWS_ACCESS_KEY_ID': credentials.access_key,
        'AWS_SECRET_ACCESS_KEY': credentials.secret_key,
        'AWS_SESSION_TOKEN': credentials.token,
    }

    args = _build_args(endpoint, region_name, metadata)

    return {
        'command': 'mcp-proxy-for-aws',
        'args': args,
        'env': environment_variables,
    }


def _build_args(endpoint: str, region_name: str, metadata: Optional[Dict[str, str]] = None):
    """Build command line arguments for mcp-proxy-for-aws."""
    args = [
        endpoint,
        '--log-level',
        'DEBUG',
        '--region',
        region_name,
    ]

    # Add metadata arguments if provided
    if metadata:
        args.append('--metadata')
        for key, value in metadata.items():
            args.append(f'{key}={value}')

    return args
