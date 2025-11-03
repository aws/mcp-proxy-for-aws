"""Integration tests for dynamic tool behavior through the proxy."""

import fastmcp
import logging
import pytest


logger = logging.getLogger(__name__)


@pytest.mark.asyncio(loop_scope='module')
async def test_proxy_reflects_tool_addition(mcp_client: fastmcp.Client, is_using_agentcore: bool):
    """Test that when backend dynamically adds a tool, proxy reflects it on next list_tools call."""
    if is_using_agentcore:
        pytest.skip()

    # Arrange - Get initial tool list
    initial_tools = await mcp_client.list_tools()
    initial_tool_names = [tool.name for tool in initial_tools]

    logger.info('Initial tools: %s', initial_tool_names)

    # Verify 'multiply' tool doesn't exist yet
    assert 'multiply' not in initial_tool_names, 'multiply tool should not exist initially'

    # Act - Trigger backend to dynamically add a new tool
    logger.info('Calling add_tool_multiply to add a new tool to the backend')
    add_result = await mcp_client.call_tool('add_tool_multiply', {})
    logger.info('Backend response: %s', add_result)

    # Get updated tool list
    updated_tools = await mcp_client.list_tools()
    updated_tool_names = [tool.name for tool in updated_tools]

    logger.info('Updated tools: %s', updated_tool_names)

    # Assert
    # The proxy should reflect the newly added tool
    assert 'multiply' in updated_tool_names, 'multiply tool should now exist after adding'
    assert len(updated_tools) == len(initial_tools) + 1, 'Should have one more tool'

    # Verify the new tool actually works
    logger.info('Testing the newly added multiply tool')
    multiply_result = await mcp_client.call_tool('multiply', {'x': 6, 'y': 7})

    # Extract the result (handling different response formats)
    from tests.integ.test_proxy_simple_mcp_server import get_text_content

    result_text = get_text_content(multiply_result)
    assert result_text == '42', f'multiply(6, 7) should return 42, got {result_text}'
