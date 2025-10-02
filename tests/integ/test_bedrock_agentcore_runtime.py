"""Test the features about testing connecting to agentcore runtime via the proxy."""

import boto3
import fastmcp
import os
import pytest
import pytest_asyncio
from fastmcp.client import StdioTransport
from typing import TypedDict


class AgentCoreRuntimeConfig(TypedDict):
    """AgentCore endpoint config."""

    endpoint: str
    region_name: str


RUNTIME_ENDPOINT_FMT_STR = 'https://bedrock-agentcore.{region_name}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier=DEFAULT'


def get_aws_credentials():
    """Return aws credentials for the session."""
    credentials = boto3.Session().get_credentials()
    return {
        'AWS_ACCESS_KEY_ID': credentials.access_key,
        'AWS_SECRET_ACCESS_KEY': credentials.secret_key,
        'AWS_SESSION_TOKEN': credentials.token,
    }


@pytest.fixture(scope='module')
def agentcore_runtime() -> AgentCoreRuntimeConfig:
    """Get runtime endpoint from arn in environment variable."""
    runtime_arn = os.environ.get('AGENTCORE_RUNTIME_ARN')
    if not runtime_arn:
        raise RuntimeError('Agent core runtime arn not found')
    region_name = runtime_arn.split(':')[3]
    encoded_arn = runtime_arn.replace(':', '%3A').replace('/', '%2F')

    return {
        'endpoint': RUNTIME_ENDPOINT_FMT_STR.format(
            region_name=region_name,
            encoded_arn=encoded_arn,
        ),
        'region_name': region_name,
    }


@pytest_asyncio.fixture(loop_scope='module', scope='module')
async def mcp_client(
    agentcore_runtime: AgentCoreRuntimeConfig,
):
    """Create a mcp client that connects to the remote sigv4 MCP via the proxy."""
    client = fastmcp.Client(
        StdioTransport(
            command='aws-mcp-proxy',
            args=[
                agentcore_runtime['endpoint'],
                '--service',
                'bedrock-agentcore',
                '--log-level',
                'DEBUG',
            ],
            env={'AWS_REGION': agentcore_runtime['region_name']} | get_aws_credentials(),
        ),
    )
    async with client:
        yield client


@pytest.mark.asyncio(loop_scope='module')
async def test_ping(mcp_client: fastmcp.Client):
    """Test ping."""
    await mcp_client.ping()


@pytest.mark.asyncio(loop_scope='module')
async def test_list_tools(mcp_client: fastmcp.Client):
    """Test list tool."""
    tools = await mcp_client.list_tools()
    assert tools


def test_call_tool():
    """TODO."""
    pass


def test_handle_elicitation():
    """TODO."""
    pass


def test_handle_sampling():
    """TODO."""
    pass
