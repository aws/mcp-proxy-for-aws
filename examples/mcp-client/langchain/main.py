"""
AWS MCP Client Example: LangChain Agent Integration

This example demonstrates how to use the AWS IAM MCP Client library (aws-iam-mcp-client)
with LangChain to connect an AI agent to an MCP server on Amazon Bedrock AgentCore using
AWS IAM authentication.

How to use this example:
========================
1. Set your AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Update MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE with your MCP server details
3. Run: uv run main.py to ask the agent what it can do
"""

import asyncio
from contextlib import asynccontextmanager

from mcp.client.session import ClientSession

from langchain_aws import ChatBedrock
from langchain.agents import create_agent as create_langchain_agent
from langchain_mcp_adapters.tools import load_mcp_tools

from mcp_proxy_for_aws.client import aws_iam_mcp_client


# Set the MCP Server URL, AWS Region, and AWS Service (see README.md for details)
MCP_SERVER_URL = '<MCP Server URL>'
MCP_SERVER_REGION = '<MCP Server Region>'
MCP_SERVER_AWS_SERVICE = '<AWS Service>'  # e.g. "bedrock-agentcore"


# The async context manager automatically manages the underlying resources.
@asynccontextmanager
async def create_agent():
    """Create a LangChain agent with IAM authenticated access to an MCP server."""

    # Set up access to an LLM
    model = ChatBedrock(model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0')

    # Initialize an MCP client with IAM authentication
    iam_client = aws_iam_mcp_client(
        endpoint=MCP_SERVER_URL, aws_region=MCP_SERVER_REGION, aws_service=MCP_SERVER_AWS_SERVICE
    )

    # Initialize an MCP session with the IAM client
    async with iam_client as (read, write, session_id_callback):
        async with ClientSession(read, write) as session:
            # Retrieve the MCP tools from the session
            mcp_tools = await load_mcp_tools(session)

            # Create an agent with access to the MCP tools
            agent = create_langchain_agent(model=model, tools=mcp_tools)

            # Return the agent as a callable function
            async def agent_callable(user_input: str) -> str:
                """Call the agent with the given input."""
                result = await agent.ainvoke({'messages': [('user', user_input)]})
                return result['messages'][-1].content

            yield agent_callable


async def main():
    """Create and run a LangChain agent with access to the MCP server."""
    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
