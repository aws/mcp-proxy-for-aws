# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Example: Using MCP Proxy for AWS as a client for Strands Agent integration.

This example demonstrates how to use the aws_iam_streamablehttp_client with the Strands SDK
to connect an AI agent to an MCP server using AWS IAM authentication.

Setup:
======
1. Configure AWS credentials (via AWS CLI, environment variables, or IAM roles)
2. Set the following environment variables (or create a .env file):
   - MCP_URL: The URL of your MCP server
   - MCP_SERVICE: AWS service hosting the MCP server (e.g., "bedrock-agentcore")
   - MCP_REGION: AWS region where the MCP server is hosted (e.g., "us-west-2")
3. Run: `uv run main.py`

Example .env file:
==================
MCP_SERVER_URL=https://example.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp
MCP_SERVER_AWS_SERVICE=bedrock-agentcore
MCP_SERVER_REGION=us-west-2
"""

import asyncio
import dotenv
import os
from contextlib import asynccontextmanager
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client
from strands import Agent
from strands.tools.mcp.mcp_client import MCPClient


# Load configuration from .env file (if present)
dotenv.load_dotenv()

# MCP server configuration - can be set via environment variables or .env file
try:
    MCP_URL = os.environ['MCP_SERVER_URL']
    MCP_SERVICE = os.environ['MCP_SERVER_AWS_SERVICE']
    MCP_REGION = os.environ['MCP_SERVER_REGION']
except KeyError:
    raise AssertionError('Please follow the README to setup environment variables.')


@asynccontextmanager
async def create_agent():
    """Create a Strands agent with AWS IAM-authenticated MCP server access.

    This function demonstrates the key integration pattern:
    1. Define an aws_iam_streamablehttp_client factory function with the MCP server details
    2. Initialize a Strands MCPClient with the client factory
    3. Retrieve the available tools from the MCP server
    4. Create an agent with access to those tools
    5. Return a callable interface to communicate with the agent
    """

    # Define an MCP client factory function for AWS IAM authentication
    def mcp_client_factory():
        return aws_iam_streamablehttp_client(
            endpoint=MCP_URL, aws_region=MCP_REGION, aws_service=MCP_SERVICE
        )

    # Create a Strands MCP client and retrieve the tools from the server
    with MCPClient(mcp_client_factory) as mcp_client:
        mcp_tools = mcp_client.list_tools_sync()

        # Create the agent with access to the tools
        agent = Agent(tools=mcp_tools, callback_handler=None)

        # Yield a callable interface to the agent
        async def agent_callable(user_input: str) -> str:
            """Send a message to the agent and return its response."""
            result = agent(user_input)
            return str(result)

        yield agent_callable


async def main():
    """Run the agent example by asking it to list its available tools."""
    # Validate required environment variables
    if not MCP_URL or not MCP_REGION or not MCP_SERVICE:
        raise ValueError(
            'Please set MCP_SERVER_URL, MCP_SERVER_REGION, and MCP_SERVER_AWS_SERVICE environment variables or create an .env file.'
        )

    # Create and run the agent
    async with create_agent() as agent:
        result = await agent('Show me your available tools.')
        print(f'\n{result}')


if __name__ == '__main__':
    asyncio.run(main())
