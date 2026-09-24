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

"""Proxy behaviour on both MCP protocol versions.

MCP's older protocol versions open with a handshake: the client sends `initialize` and the
server answers with what it supports. The newest one, `2026-07-28`, dropped the handshake --
every request stands on its own. fastmcp 4 negotiates whichever the client asks for.

That difference matters to a proxy. With no handshake, `InitializeMiddleware.on_initialize`
never runs, so its `on_request` fallback is what connects the backend and forwards the
backend's instructions instead. The rest of the integ suite only exercises the older protocol
(it is the only one with `ping` and `ctx.elicit()`), so these tests cover the newer one.
"""

import logging
import pytest
from .conftest import RemoteMCPServerConfiguration
from .mcp.simple_mcp_client import build_mcp_client


logger = logging.getLogger(__name__)

# 'legacy' pins the older handshake protocol; 'auto' lets fastmcp negotiate, which
# against a fastmcp 4 server settles on the newer handshake-free 2026-07-28.
PROTOCOLS = ['legacy', 'auto']


@pytest.mark.parametrize('mode', PROTOCOLS)
@pytest.mark.asyncio(loop_scope='function')
async def test_proxy_serves_tools_on_both_protocols(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """Listing tools and calling one both work on either protocol version.

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
        assert result.content[0].text == 'Hello Superman'  # type: ignore[union-attr]


@pytest.mark.parametrize('mode', PROTOCOLS)
@pytest.mark.asyncio(loop_scope='function')
async def test_backend_instructions_reach_the_client_on_both_protocols(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """The client is told the backend's instructions, not the proxy's own placeholder.

    The two protocol versions read instructions at different moments, so `InitializeMiddleware`
    needs a different route for each. MCP SDK v2 removed the private attribute the older code
    wrote through, and a mock-based unit test could not catch that, so assert it for real here.
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


@pytest.mark.parametrize('mode', PROTOCOLS)
@pytest.mark.asyncio(loop_scope='function')
async def test_read_only_hint_survives_on_both_protocols(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """Tool annotations arrive under the MCP SDK v2 `read_only_hint` field name.

    `--read-only` filters on this hint, so reading the wrong field name filters every tool away
    instead of failing.
    """
    client = build_mcp_client(
        endpoint=remote_mcp_server_configuration['endpoint'],
        region_name=remote_mcp_server_configuration['region_name'],
        mode=mode,
    )

    async with client:
        annotated = [tool for tool in await client.list_tools() if tool.annotations is not None]
        assert annotated, f'backend exposed no annotated tools on mode={mode}'

        hints = {tool.name: tool.annotations.read_only_hint for tool in annotated}  # type: ignore[union-attr]
        logger.info('mode=%s read_only_hint=%s', mode, hints)
        assert any(hint is not None for hint in hints.values()), (
            f'every read_only_hint read as unset on mode={mode}, which would hide all tools '
            'in --read-only mode'
        )


@pytest.mark.parametrize('mode', PROTOCOLS)
@pytest.mark.asyncio(loop_scope='function')
async def test_read_only_mode_keeps_read_only_tools_and_drops_the_rest(
    remote_mcp_server_configuration: RemoteMCPServerConfiguration, mode: str
):
    """`--read-only` hides write tools and keeps read-only ones.

    The guard that matters most: the filter reads `read_only_hint`, and if that name is ever
    wrong every tool reads as a write tool and the proxy serves an empty list. That is a silent
    failure -- the client just sees no tools -- so assert both halves, that the read-only tool
    survives and that the others are gone.
    """
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
        assert result.content[0].text == 'read-only ok'  # type: ignore[union-attr]

        # A write tool must be refused rather than silently forwarded.
        refused = await client.call_tool('greet', {'name': 'Superman'}, raise_on_error=False)
        assert refused.is_error, f'write tool was not refused in read-only mode on mode={mode}'
