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
        ('aws___suggest_aws_commands', {'query': 'how to list my lambda functions'}),
        ('aws___search_documentation', {'search_phrase': 'S3 bucket versioning'}),
        (
            'aws___recommend',
            {'url': 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html'},
        ),
        (
            'aws___read_documentation',
            {'url': 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html'},
        ),
        (
            'aws___get_regional_availability',
            {'resource_type': 'cfn', 'region': 'us-east-1'},
        ),
        ('aws___call_aws', {'cli_command': 'aws s3 ls', 'max_results': 10}),
    ],
    ids=[
        'list_regions',
        'suggest_aws_commands',
        'search_documentation',
        'recommend',
        'read_documentation',
        'get_regional_availability',
        'call_aws',
    ],
)
@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_tools(aws_mcp_client: fastmcp.Client, tool_name: str, params: dict):
    """Test AWS MCP tools with minimal valid params."""
    response = await aws_mcp_client.call_tool(tool_name, params)
    verify_json_response(response)


@pytest.mark.asyncio(loop_scope='module')
async def test_aws_mcp_tools_retrieve_agent_sop(aws_mcp_client: fastmcp.Client):
    """Test aws___retrieve_agent_sop by retrieving the list of available SOPs."""
    # Step 1: Call retrieve_agent_sop with empty params to get list of available SOPs
    list_sops_response = await aws_mcp_client.call_tool('aws___retrieve_agent_sop')

    list_sops_response_text = verify_response_content(list_sops_response)

    # Parse SOP names from text (format: "* sop_name : description")
    sop_names = []
    for line in list_sops_response_text.split('\n'):
        line = line.strip()
        if line.startswith('*') and ':' in line:
            # Extract the SOP name between '*' and ':'
            sop_name = line.split('*', 1)[1].split(':', 1)[0].strip()
            if sop_name:
                sop_names.append(sop_name)

    assert len(sop_names) > 0, (
        f'No SOPs found in response. Response: {list_sops_response_text[:200]}...'
    )
    logger.info('Found %d SOPs: %s', len(sop_names), sop_names)

    # Step 2: Test retrieving the first SOP
    test_script = sop_names[0]
    logger.info('Testing with SOP: %s', test_script)

    response = await aws_mcp_client.call_tool(
        'aws___retrieve_agent_sop', {'sop_name': test_script}
    )

    verify_response_content(response)
