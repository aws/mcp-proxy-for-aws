"""
AWS IAM MCP Client Example: Microsoft Agent Framework Integration

This example demonstrates how to use the AWS IAM MCP Client library (aws-iam-mcp-client) with
the Microsoft Agent Framework to connect an AI agent to an MCP server on Amazon Bedrock AgentCore
using AWS IAM authentication.

How to use this example:
========================
1. Set your AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Set your OPENAI_API_KEY environment variable (for the GPT model)
2. Update MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE with your MCP server details
4. Run: `uv run main.py` to ask the agent what it can do
"""

import asyncio
from typing import Any
import dotenv
import os
from contextlib import asynccontextmanager

from agent_framework import ChatAgent
from agent_framework.openai import OpenAIChatClient
from agent_framework._mcp import MCPStreamableHTTPTool

from mcp_proxy_for_aws.client import aws_iam_mcp_client


# Set the MCP Server URL, AWS Region, and AWS Service (see README.md for details)
MCP_SERVER_URL = '<MCP Server URL>'
MCP_SERVER_REGION = '<MCP Server Region>'
MCP_SERVER_AWS_SERVICE = '<AWS Service>'  # e.g. "bedrock-agentcore"


# The async context manager automatically manages the underlying resources.
@asynccontextmanager
async def create_agent():
    """Create an Agent Framework agent with IAM authenticated access to an MCP server."""

    # Set up access to an LLM
    chat_client = OpenAIChatClient(model_id='gpt-4.1-mini', api_key=os.getenv('OPENAI_API_KEY'))

    # Initialize an IAM MCP client factory
    iam_client_factory = lambda: aws_iam_mcp_client(
        endpoint=MCP_SERVER_URL, aws_region=MCP_SERVER_REGION, aws_service=MCP_SERVER_AWS_SERVICE
    )

    # Retrieve the MCP tools from the IAM client factory using the Agent Framework MCPStreamableHTTPTool
    mcp_tools = MCPStreamableHTTPTool(name='MCP Tools', url=MCP_SERVER_URL)
    mcp_tools.get_mcp_client = iam_client_factory

    async with mcp_tools:
        # Create an agent with access to the MCP tools
        agent = ChatAgent(chat_client=chat_client, tools=[mcp_tools])

        # Return the agent as a callable function
        async def agent_callable(user_input: str) -> str:
            """Call the agent with the given input."""
            result = await agent.run(user_input)
            return str(result)

        yield agent_callable


async def main():
    """Create and run an Agent Framework agent with access to the MCP server."""

    # This example requires the OPENAI_API_KEY to be set as an environment variable or in an .env file
    dotenv.load_dotenv()
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY environment variable is required')

    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
