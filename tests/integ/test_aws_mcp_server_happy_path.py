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

"""Happy path integration tests for AWS MCP Server at https://aws-mcp.us-east-1.api.aws/mcp."""

import fastmcp
import json
import logging
import pytest
from fastmcp.client.client import CallToolResult
from tests.integ.test_proxy_simple_mcp_server import get_text_content


logger = logging.getLogger(__name__)


@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_ping(aws_mcp_client: fastmcp.Client):
    """Test ping to AWS MCP Server."""
    await aws_mcp_client.ping()


@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_list_tools(aws_mcp_client: fastmcp.Client):
    """Test list tools from AWS MCP Server."""
    tools = await aws_mcp_client.list_tools()

    assert len(tools) > 0, f'AWS MCP Server should have tools (got {len(tools)})'


def verify_response_content(response: CallToolResult):
    """Verify that a tool call response is successful and contains text content.

    Args:
        response: The CallToolResult from an MCP tool call

    Returns:
        str: The extracted text content from the response

    Raises:
        AssertionError: If response indicates an error or has empty content
    """
    assert response.is_error is False, (
        f'is_error returned true. Returned response body: {response}.'
    )
    assert len(response.content) > 0, f'Empty result list in response. Response: {response}'

    response_text = get_text_content(response)
    assert len(response_text) > 0, f'Empty response text. Response: {response}'

    return response_text


def verify_json_response(response: CallToolResult):
    """Verify that a tool call response is successful and contains valid JSON data.

    Args:
        response: The CallToolResult from an MCP tool call

    Raises:
        AssertionError: If response indicates an error, has empty content,
                       contains invalid JSON, or JSON data is empty
    """
    response_text = verify_response_content(response)

    # Verify response_text is valid JSON
    try:
        response_data = json.loads(response_text)
    except json.JSONDecodeError:
        raise AssertionError(f'Response text is not valid JSON. Response text: {response_text}')

    assert len(response_data) > 0, f'Empty JSON content in response. Response: {response}'


@pytest.mark.parametrize(
    'tool_name,params',
    [
        ('aws___list_regions', {}),
        ('aws___call_aws', {'cli_command': 'aws lambda list-functions', 'max_results': 10}),
    ],
    ids=[
        'list_regions',
        'list_lambda_functions',
    ],
)
@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_tools(aws_mcp_client: fastmcp.Client, tool_name: str, params: dict):
    """Test AWS MCP tools with minimal valid params."""
    response = await aws_mcp_client.call_tool(tool_name, params)
    verify_json_response(response)


@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_tools_retrieve_skill(aws_mcp_client: fastmcp.Client):
    """Test aws___retrieve_skill by retrieving a skill."""
    test_skill = 'creating-production-vpc-multi-az'
    logger.info('Testing with skill: %s', test_skill)

    response = await aws_mcp_client.call_tool('aws___retrieve_skill', {'skill_name': test_skill})

    verify_response_content(response)
