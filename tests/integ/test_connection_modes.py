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

"""Proxy behaviour for both ways a client can open a connection.

A client may open with a handshake -- it sends `initialize` and the server answers with what
it supports -- or without one, in which case every request stands on its own. The client
chooses.

That choice matters to a proxy. Without a handshake, `InitializeMiddleware.on_initialize`
never runs, so its `on_request` fallback is what connects the backend and forwards the
backend's instructions. The rest of the integ suite only exercises handshake connections
(they alone carry `ping` and `ctx.elicit()`), so these tests cover the other kind.
"""

import logging
import pytest
from .conftest import RemoteMCPServerConfiguration
from .mcp.simple_mcp_client import build_mcp_client
from fastmcp.client.client import CallToolResult
from mcp.types import TextContent


logger = logging.getLogger(__name__)


def _text_of(result: CallToolResult) -> str:
    """Return the text of a tool result's first content block."""
    block = result.content[0]
    assert isinstance(block, TextContent), f'expected text content, got {type(block).__name__}'
    return block.text


# 'legacy' pins a handshake connection; 'auto' negotiates, settling on a handshake-free one.
MODES = ['legacy', 'auto']


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.asyncio(loop_scope='function')
async def test_proxy_serves_tools_either_way(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """Listing tools and calling one both work whichever way the client opens.

    Without a handshake this is what proves the `on_request` fallback connected the backend:
    otherwise the client reaches `tools/list` against a proxy that never dialled the backend.
    """
    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
        mode=mode,
    )

    async with client:
        tools = await client.list_tools()
        logger.info('mode=%s tools=%s', mode, [tool.name for tool in tools])
        assert len(tools) > 0, f'no tools listed on mode={mode}'

        result = await client.call_tool('greet', {'name': 'Superman'})
        assert _text_of(result) == 'Hello Superman'


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.asyncio(loop_scope='function')
async def test_backend_instructions_reach_the_client_either_way(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """The client is told the backend's instructions, not the proxy's own placeholder.

    The two modes read instructions at different moments, so `InitializeMiddleware`
    needs a different route for each.
    """
    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
        mode=mode,
    )

    async with client:
        instructions = client.instructions
        logger.info('mode=%s instructions=%r', mode, instructions)
        assert instructions, f'no instructions forwarded on mode={mode}'
        assert 'MCP Proxy for AWS provides access to SigV4' not in instructions, (
            f'client got the proxy placeholder instead of the backend instructions on mode={mode}'
        )


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.asyncio(loop_scope='function')
async def test_read_only_hint_survives_either_way(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration,
    is_using_agentcore: bool,
    mode: str,
):
    """Tool annotations arrive under the `read_only_hint` field name.

    `--read-only` filters on this hint, so reading the wrong field name filters every tool away
    instead of failing.
    """
    if is_using_agentcore:
        pytest.skip()

    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
        mode=mode,
    )

    async with client:
        hints = {
            tool.name: tool.annotations.read_only_hint
            for tool in await client.list_tools()
            if tool.annotations is not None
        }
        assert hints, f'backend exposed no annotated tools on mode={mode}'
        logger.info('mode=%s read_only_hint=%s', mode, hints)
        assert any(hint is not None for hint in hints.values()), (
            f'every read_only_hint read as unset on mode={mode}, which would hide all tools '
            'in --read-only mode'
        )


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.asyncio(loop_scope='function')
async def test_read_only_mode_keeps_read_only_tools_and_drops_the_rest(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration,
    is_using_agentcore: bool,
    mode: str,
):
    """`--read-only` hides write tools and keeps read-only ones.

    The guard that matters most: the filter reads `read_only_hint`, and if that name is ever
    wrong every tool reads as a write tool and the proxy serves an empty list. That is a silent
    failure -- the client just sees no tools -- so assert both halves, that the read-only tool
    survives and that the others are gone.
    """
    if is_using_agentcore:
        pytest.skip()

    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
        mode=mode,
        extra_args=['--read-only'],
    )

    async with client:
        names = [tool.name for tool in await client.list_tools()]
        logger.info('mode=%s read-only tools=%s', mode, names)
        assert names == ['read_only_probe'], f'unexpected read-only tool list on mode={mode}'

        result = await client.call_tool('read_only_probe', {})
        assert _text_of(result) == 'read-only ok'

        # A write tool must be refused rather than silently forwarded.
        refused = await client.call_tool('greet', {'name': 'Superman'}, raise_on_error=False)
        assert refused.is_error, f'write tool was not refused in read-only mode on mode={mode}'
