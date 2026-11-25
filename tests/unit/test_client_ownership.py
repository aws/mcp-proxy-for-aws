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

"""Owned library clients are closed on each context exit path."""

import asyncio
import httpx2
import pytest
from botocore.credentials import Credentials
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client


@pytest.mark.parametrize('exit_mode', ['normal', 'error', 'cancel'])
async def test_library_closes_created_http_client(exit_mode: str) -> None:
    """The wrapper owns clients it creates through its factory."""
    clients: list[httpx2.AsyncClient] = []

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
    ) -> httpx2.AsyncClient:
        client = httpx2.AsyncClient(headers=headers, timeout=timeout, auth=auth, trust_env=False)
        clients.append(client)
        return client

    async def use() -> None:
        async with aws_iam_streamablehttp_client(
            'http://127.0.0.1:1/mcp',
            'execute-api',
            'us-east-1',
            credentials=Credentials('synthetic', 'synthetic'),
            httpx_client_factory=factory,
        ):
            assert not clients[-1].is_closed
            if exit_mode == 'error':
                raise ValueError('consumer failure')
            if exit_mode == 'cancel':
                raise asyncio.CancelledError

    try:
        if exit_mode == 'error':
            with pytest.raises(ExceptionGroup, match='TaskGroup') as caught:
                await use()
            assert isinstance(caught.value.exceptions[0], ValueError)
        elif exit_mode == 'cancel':
            with pytest.raises(asyncio.CancelledError):
                await use()
        else:
            await use()
        assert len(clients) == 1 and clients[0].is_closed
    finally:
        for client in clients:
            await client.aclose()


async def test_library_closes_after_external_anyio_cancellation() -> None:
    """Actual cancellation of the consumer scope still closes the owned HTTP client."""
    import anyio

    clients: list[httpx2.AsyncClient] = []
    scopes: list[anyio.CancelScope] = []
    started = anyio.Event()

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
    ) -> httpx2.AsyncClient:
        client = httpx2.AsyncClient(headers=headers, timeout=timeout, auth=auth, trust_env=False)
        clients.append(client)
        return client

    async def consume() -> None:
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            async with aws_iam_streamablehttp_client(
                'http://127.0.0.1:1/mcp',
                'execute-api',
                'us-east-1',
                credentials=Credentials('synthetic', 'synthetic'),
                httpx_client_factory=factory,
            ):
                started.set()
                await anyio.sleep_forever()

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(consume)
            await started.wait()
            scopes[0].cancel()
        assert len(clients) == 1 and clients[0].is_closed
    finally:
        for client in clients:
            await client.aclose()
