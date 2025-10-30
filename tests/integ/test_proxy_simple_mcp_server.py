"""Test the features about testing connecting to remote MCP Server runtime via the proxy."""

import fastmcp
import json
import logging
import pytest
from mcp.types import TextContent


logger = logging.getLogger(__name__)


def get_text_content(response) -> str:
    """Extract text content from MCP response, handling different content types."""
    assert len(response.content) > 0, 'No content returned'
    content = response.content[0]

    if isinstance(content, TextContent):
        return content.text
    elif hasattr(content, 'text'):
        return content.text
    else:
        raise AssertionError(f'Content is not text content: {type(content)}')


@pytest.mark.asyncio(loop_scope='module')
async def test_ping(mcp_client: fastmcp.Client):
    """Test ping."""
    await mcp_client.ping()


@pytest.mark.asyncio(loop_scope='module')
async def test_list_tools(mcp_client: fastmcp.Client):
    """Test list tool."""
    tools = await mcp_client.list_tools()

    failure_message = f'MCP Server does not contain any Tools (ListTools = {tools})'
    assert len(tools) > 0, failure_message


@pytest.mark.asyncio(loop_scope='module')
async def test_call_tool(mcp_client: fastmcp.Client):
    """Test call tool."""
    name = 'Superman'
    expected_response = f'Hello {name}'

    tool_input = {'name': name}
    actual_response = await mcp_client.call_tool('greet', tool_input)

    actual_text = get_text_content(actual_response)
    failure_message = f"Tool 'greet' did not return the expected result (Returned {actual_text}) (Expected {expected_response})"
    assert actual_text == expected_response, failure_message


@pytest.mark.asyncio(loop_scope='module')
async def test_handle_elicitation_when_accepting(
    mcp_client: fastmcp.Client, is_using_agentcore: bool
):
    """Test calling tool which supports elicitation and accepting it."""
    if is_using_agentcore:
        pytest.skip()

    expected_response = 'Nice to meet you - Elicitation success'

    tool_input = {'elicitation_expected': 'Accept'}
    actual_response = await mcp_client.call_tool('elicit_for_my_name', tool_input)

    actual_text = get_text_content(actual_response)
    failure_message = f"Tool 'elicit_for_my_name' did not return the expected result (Returned {actual_text}) (Expected {expected_response})"
    assert actual_text == expected_response, failure_message


@pytest.mark.asyncio(loop_scope='module')
async def test_handle_elicitation_when_declining(
    mcp_client: fastmcp.Client, is_using_agentcore: bool
):
    """Test calling tool which supports elicitation and declining it."""
    if is_using_agentcore:
        pytest.skip()

    expected_response = 'Information not provided'

    tool_input = {'elicitation_expected': 'Decline'}
    actual_response = await mcp_client.call_tool('elicit_for_my_name', tool_input)

    actual_text = get_text_content(actual_response)
    failure_message = f"Tool 'elicit_for_my_name' did not return the expected result (Returned {actual_text}) (Expected {expected_response})"
    assert actual_text == expected_response, failure_message


@pytest.mark.asyncio(loop_scope='module')
async def test_handle_sampling(mcp_client: fastmcp.Client):
    """TODO."""
    pass


@pytest.mark.asyncio(loop_scope='module')
async def test_metadata_injection_aws_region(
    mcp_client: fastmcp.Client, remote_mcp_server_configuration
):
    """Test that AWS_REGION is automatically injected and received by the server.

    This integration test verifies the full flow:
    1. Client makes a request through the proxy
    2. Proxy injects AWS_REGION into the _meta field
    3. Server receives the request with metadata
    4. Server echoes back the metadata it received
    5. We verify AWS_REGION was correctly transmitted
    """
    # Call the echo_metadata tool which returns the _meta field it received
    actual_response = await mcp_client.call_tool('echo_metadata', {})

    # Extract the response content
    actual_text = get_text_content(actual_response)

    # Parse the JSON response
    response_data = json.loads(actual_text)

    # Verify that AWS_REGION was injected and received by the server
    assert 'received_meta' in response_data, (
        f'Response should contain received_meta: {response_data}'
    )
    assert response_data['received_meta'] is not None, 'Metadata should not be None'
    assert 'AWS_REGION' in response_data['received_meta'], (
        f'Metadata should contain AWS_REGION: {response_data["received_meta"]}'
    )
