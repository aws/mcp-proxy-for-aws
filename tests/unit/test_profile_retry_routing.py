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

"""Behavioral retry checks using the middleware installed by run_proxy."""

import httpx2
import mcp.types as mt
import pytest
import sys
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.server.middleware.error_handling import RetryMiddleware
from fastmcp.tools import ToolResult
from mcp_proxy_for_aws import server
from mcp_proxy_for_aws.middleware import profile_switcher
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock


async def _exercise(
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    error: Exception,
    retries: int,
    *,
    permanent: bool = False,
) -> tuple[list[str], ToolResult | None]:
    """Run calls through the actual server middleware registration."""
    proxy = FastMCP('Retry regression')
    actors: list[str] = []
    result: ToolResult | None = None

    async def invoke(actor: str, arguments: dict[str, Any]) -> ToolResult:
        actors.append(actor)
        assert 'aws_profile' not in arguments
        if permanent or len(actors) == 1:
            raise error
        return ToolResult(
            content=[mt.TextContent(type='text', text=actor)],
            structured_content={'profile': actor},
        )

    class ProfileClient:
        """Controlled upstream seam; middleware dispatch remains real."""

        def __init__(self, transport: str) -> None:
            self.profile = transport

        async def __aenter__(self) -> 'ProfileClient':
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def call_tool(self, name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
            value = await invoke(self.profile, arguments)
            return SimpleNamespace(
                content=value.content,
                structured_content=value.structured_content,
                meta=None,
                is_error=False,
            )

    async def run(**kwargs: Any) -> None:
        nonlocal result
        for middleware in proxy.middleware:
            if isinstance(middleware, RetryMiddleware):
                middleware.base_delay = 0

        context = MiddlewareContext(
            message=mt.CallToolRequestParams(
                name='aws___run_script', arguments={'aws_profile': profile}
            ),
            method='tools/call',
        )

        async def default_call(context: MiddlewareContext) -> ToolResult:
            return await invoke('A', context.message.arguments)

        if (
            permanent
            or retries == 0
            or not isinstance(
                error,
                (ConnectionError, TimeoutError, httpx2.NetworkError, httpx2.TimeoutException),
            )
        ):
            with pytest.raises(ToolError):
                await proxy._run_middleware(context, default_call)
        else:
            result = await proxy._run_middleware(context, default_call)

    def transport(*args: Any, **kwargs: Any) -> str:
        return args[5]

    monkeypatch.delenv('AWS_MCP_PROXY_PROFILES', raising=False)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'mcp-proxy',
            'http://127.0.0.1/mcp',
            '--profile',
            'A',
            'B',
            '--service',
            'execute-api',
            '--region',
            'us-east-1',
            '--retries',
            str(retries),
        ],
    )
    monkeypatch.setattr(server, 'determine_aws_region', lambda *args: 'us-east-1')
    monkeypatch.setattr(server, 'create_transport_with_sigv4', lambda *args: None)
    monkeypatch.setattr(
        server,
        'AWSMCPProxyClientFactory',
        lambda *args: SimpleNamespace(disconnect=AsyncMock(), connected=True),
    )
    monkeypatch.setattr(server, 'FastMCPProxy', lambda **kwargs: proxy)
    monkeypatch.setattr(profile_switcher, 'determine_aws_region', lambda *args: 'us-east-1')
    monkeypatch.setattr(profile_switcher, 'create_transport_with_sigv4', transport)

    async def selected_client(self: Any, profile: str) -> ProfileClient:
        return ProfileClient(profile)

    monkeypatch.setattr(
        profile_switcher.ProfileOverrideMiddleware, '_get_profile_client', selected_client
    )
    monkeypatch.setattr(proxy, 'run_async', run)
    await server.run_proxy(server.parse_args())
    return actors, result


@pytest.mark.parametrize('profile', ['A', 'B'])
@pytest.mark.parametrize('error_type', [ConnectionError, httpx2.ReadTimeout, httpx2.ConnectError])
async def test_retry_recovers_on_both_profile_routes(
    monkeypatch: pytest.MonkeyPatch, profile: str, error_type: type[Exception]
) -> None:
    """Transient failures get a second attempt with the same selected actor."""
    actors, result = await _exercise(monkeypatch, profile, error_type('transient'), 1)
    assert actors == [profile, profile]
    assert result is not None and result.structured_content == {'profile': profile}


@pytest.mark.parametrize('profile', ['A', 'B'])
@pytest.mark.parametrize('retries', [0, 1])
async def test_profile_retry_budget(
    monkeypatch: pytest.MonkeyPatch, profile: str, retries: int
) -> None:
    """Persistent transport failures respect the opt-in retry budget."""
    actors, _ = await _exercise(
        monkeypatch, profile, httpx2.ReadTimeout('persistent'), retries, permanent=True
    )
    assert actors == [profile] * (retries + 1)


@pytest.mark.parametrize('profile', ['A', 'B'])
@pytest.mark.parametrize('status', [401, 503])
async def test_http_status_is_not_automatically_retried(
    monkeypatch: pytest.MonkeyPatch, profile: str, status: int
) -> None:
    """HTTP status errors remain outside the transient transport policy."""
    response = httpx2.Response(status, request=httpx2.Request('POST', 'http://127.0.0.1/mcp'))
    error = httpx2.HTTPStatusError('refusal', request=response.request, response=response)
    actors, _ = await _exercise(monkeypatch, profile, error, 1)
    assert actors == [profile]
