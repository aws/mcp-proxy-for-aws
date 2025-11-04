"""
AWS MCP Client Example: LlamaIndex Agent Integration

This example demonstrates how to use the AWS IAM MCP Client library (aws-iam-mcp-client)
with LlamaIndex to connect an AI agent to an MCP server on Amazon Bedrock AgentCore using
AWS IAM authentication.

How to use this example:
========================
1. Set your AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Set your OPENAI_API_KEY environment variable (for the GPT model)
3. Update MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE with your MCP server details
4. Run: uv run main.py to ask the agent what it can do
"""

# Ignore Pydantic UserWarnings that are not relevant to this example
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='pydantic.*')


import asyncio
import dotenv
import os
from contextlib import asynccontextmanager

from llama_index.core.agent.workflow import ReActAgent
from llama_index.llms.openai import OpenAI
from llama_index.tools.mcp import McpToolSpec
from mcp.client.session import ClientSession

from mcp_proxy_for_aws.client import aws_iam_mcp_client


# Set the MCP Server URL, AWS Region, and AWS Service (see README.md for details)
MCP_SERVER_URL = '<MCP Server URL>'
MCP_SERVER_REGION = '<MCP Server Region>'
MCP_SERVER_AWS_SERVICE = '<AWS Service>'  # e.g. "bedrock-agentcore"


@asynccontextmanager
async def create_agent():
    """Create a LlamaIndex agent with IAM authenticated access to an MCP server."""

    # Set up access to an LLM
    model = OpenAI(model='gpt-4.1-mini', api_key=os.getenv('OPENAI_API_KEY'))

    # Initialize an MCP client with IAM authentication
    iam_client = aws_iam_mcp_client(
        endpoint=MCP_SERVER_URL, aws_region=MCP_SERVER_REGION, aws_service=MCP_SERVER_AWS_SERVICE
    )

    # Initialize an MCP session with the IAM client
    async with iam_client as (read_stream, write_stream, session_id_callback):
        async with ClientSession(read_stream, write_stream) as session:
            # Retrieve the MCP tools from the session using the LlamaIndex MCPToolSpec
            mcp_tools = await McpToolSpec(client=session).to_tool_list_async()

            # Create an agent with access to the MCP tools
            agent = ReActAgent(llm=model, tools=mcp_tools)

            # Return the agent as a callable function
            async def agent_callable(user_input: str) -> str:
                """Call the agent with the given input."""
                response = await agent.run(user_msg=user_input)
                return str(response)

            yield agent_callable


async def main():
    """Create and run an LlamaIndex agent with access to the MCP server."""

    # This example requires OPENAI_API_KEY to be set as an environment variable or in an .env file
    dotenv.load_dotenv()
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY environment variable is required')

    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
