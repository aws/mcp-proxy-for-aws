"""
AWS IAM MCP Client Example: Strands Agent Integration

This example demonstrates how to use the AWS IAM MCP Client library (aws-iam-mcp-client)
with the Strands SDK to connect an AI agent to an MCP server on Amazon Bedrock AgentCore
using AWS IAM authentication.

How to use this example:
========================
1. Set your AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Update MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE with your MCP server details
3. Run: `uv run main.py` to ask the agent what it can do
"""

import asyncio
from contextlib import asynccontextmanager

from strands import Agent
from strands.tools.mcp.mcp_client import MCPClient

from mcp_proxy_for_aws.client import aws_iam_mcp_client


# Set the MCP Server URL, AWS Region, and AWS Service (see README.md for details)
MCP_SERVER_URL = '<MCP Server URL>'
MCP_SERVER_REGION = '<MCP Server Region>'
MCP_SERVER_AWS_SERVICE = '<AWS Service>'  # e.g. "bedrock-agentcore"


# The async context manager automatically manages the underlying resources.
@asynccontextmanager
async def create_agent():
    """Create a Strands agent with IAM authenticated access to an MCP server."""

    # Initialize an IAM MCP client factory
    iam_client_factory = lambda: aws_iam_mcp_client(
        endpoint=MCP_SERVER_URL, aws_region=MCP_SERVER_REGION, aws_service=MCP_SERVER_AWS_SERVICE
    )

    # Create a Strands MCP client with the IAM client factory
    with MCPClient(iam_client_factory) as mcp_client:
        # Retrieve the MCP tools from the client
        mcp_tools = mcp_client.list_tools_sync()

        # Create an agent with access to the MCP tools
        agent = Agent(tools=mcp_tools, callback_handler=None)

        # Return the agent as a callable function
        async def agent_callable(user_input: str) -> str:
            """Call the agent with the given input."""
            result = agent(user_input)
            return str(result)

        yield agent_callable


async def main():
    """Create and run a Strands agent with access to the MCP server."""
    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
