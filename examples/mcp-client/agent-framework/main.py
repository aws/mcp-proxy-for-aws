"""
AWS IAM MCP Client Example: Microsoft Agent Framework Integration

This example demonstrates how to use the aws_iam_mcp_client with the Microsoft Agent Framework
to connect an AI agent to an MCP server using AWS IAM authentication.

Setup:
======
1. Configure AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Set the following environment variables (or create a .env file):
   - MCP_URL: The URL of your MCP server
   - MCP_SERVICE: AWS service hosting the MCP server (e.g., "bedrock-agentcore")
   - MCP_REGION: AWS region where the MCP server is hosted (e.g., "us-west-2")
   - OPENAI_API_KEY: Your OpenAI API key for the LLM
3. Run: `uv run main.py`

Example .env file:
==================
MCP_SERVER_URL=https://example.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp
MCP_SERVER_AWS_SERVICE=bedrock-agentcore
MCP_SERVER_REGION=us-west-2
OPENAI_API_KEY=sk-...
"""

import asyncio
import dotenv
import os
from contextlib import asynccontextmanager

from agent_framework import ChatAgent
from agent_framework.openai import OpenAIChatClient
from agent_framework._mcp import MCPStreamableHTTPTool

from mcp_proxy_for_aws.client import aws_iam_mcp_client


# Load configuration from .env file (if present)
dotenv.load_dotenv()

# MCP server configuration - can be set via environment variables or .env file
MCP_URL = os.environ.get('MCP_SERVER_URL')
MCP_SERVICE = os.environ.get('MCP_SERVER_AWS_SERVICE')
MCP_REGION = os.environ.get('MCP_SERVER_REGION')

# OpenAI API key for the language model
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '<Your OpenAI API Key>')

# The model for the agent (using GPT-4.1 Mini as an example)
OPENAI_MODEL_ID = 'gpt-4.1-mini'


@asynccontextmanager
async def create_agent():
    """
    Create an Agent Framework agent with AWS IAM-authenticated MCP server access.

    This function demonstrates the key integration pattern:
    1. Configure an aws_iam_mcp_client factory with the MCP server details
    2. Initialize an MCPStreamableHTTPTool and add the client factory
    3. Create an agent with access to the tools provided by the MCP server
    4. Return a callable interface to communicate with the agent
    """
    # Configure the MCP client with AWS IAM authentication
    mcp_client_factory = lambda: aws_iam_mcp_client(
        endpoint=MCP_URL, aws_region=MCP_REGION, aws_service=MCP_SERVICE
    )

    # Create an Agent Framework MCP and add the client
    mcp_tools = MCPStreamableHTTPTool(name='MCP Tools', url=MCP_URL)
    mcp_tools.get_mcp_client = mcp_client_factory

    # Connect to the MCP server and create the agent
    async with mcp_tools:
        agent = ChatAgent(
            chat_client=OpenAIChatClient(model_id='gpt-4.1-mini', api_key=OPENAI_API_KEY),
            tools=[mcp_tools],
        )

        # Yield a callable interface to the agent
        async def agent_callable(user_input: str) -> str:
            """Send a message to the agent and return its response."""
            result = await agent.run(user_input)
            return str(result)

        yield agent_callable


async def main():
    """Run the agent example by asking it to list its available tools."""

    # Validate required environment variables
    if not MCP_URL or not MCP_REGION or not MCP_SERVICE or not OPENAI_API_KEY:
        raise ValueError(
            'Please set OPENAI_API_KEY, MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE environment variables or create an .env file.'
        )

    # Create and run the agent
    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
