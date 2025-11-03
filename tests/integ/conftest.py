import logging
import os
import pytest
import pytest_asyncio
from .mcp.simple_mcp_client import build_mcp_client
from typing import TypedDict


logger = logging.getLogger(__name__)


class RemoteMCPServerConfiguration(TypedDict):
    """Remote MCP Server endpoint config."""

    endpoint: str
    region_name: str


@pytest_asyncio.fixture(loop_scope='module', scope='module')
async def mcp_client(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration,
):
    """Create MCP Client fixture for using in Integ tests."""
    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
    )

    async with client:
        yield client


@pytest.fixture(scope='module')
async def is_using_agentcore():
    """Boolean param if we are currently running against AgentCore Runtime."""
    if os.environ.get('AGENTCORE_RUNTIME_ARN'):
        return True
    else:
        return False


@pytest.fixture(scope='module')
def remote_mcp_server_configuration(is_using_agentcore: bool):
    """Configuration to connect to remotely hosted MCP Server."""
    if is_using_agentcore:
        logger.info('Will use AgentCore MCP Server')
        return _build_agent_core_remote_configuration()
    else:
        logger.info('Will use remote MCP server defined with ENV variables')
        return _build_endpoint_environment_remote_configuration()


def _build_agent_core_remote_configuration():
    logger.info('Using AgentCore runtime ARN for remote MCP Server')

    runtime_arn = os.environ.get('AGENTCORE_RUNTIME_ARN')
    if not runtime_arn:
        raise RuntimeError('AGENTCORE_RUNTIME_ARN env variable not found')

    agent_core_runtime_url_format = 'https://bedrock-agentcore.{region_name}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier=DEFAULT'
    region_name = runtime_arn.split(':')[3]
    encoded_arn = runtime_arn.replace(':', '%3A').replace('/', '%2F')

    endpoint = agent_core_runtime_url_format.format(
        region_name=region_name, encoded_arn=encoded_arn
    )

    return RemoteMCPServerConfiguration(endpoint=endpoint, region_name=region_name)


def _build_endpoint_environment_remote_configuration():
    logger.info('Using Endpoint environment variable for remote MCP Server')

    remote_endpoint_url = os.environ.get('REMOTE_ENDPOINT_URL')
    if not remote_endpoint_url:
        raise RuntimeError('REMOTE_ENDPOINT_URL env variable not found')

    region_name = os.environ.get('AWS_REGION')
    if not region_name:
        logger.warning('AWS_REGION param not set. Defaulting to us-east-1')
        region_name = 'us-east-1'

    logger.info(
        'Starting server with config - remote_endpoint_url=%s and region_name=%s',
        remote_endpoint_url,
        region_name,
    )

    return RemoteMCPServerConfiguration(
        endpoint=remote_endpoint_url,
        region_name=region_name,
    )
