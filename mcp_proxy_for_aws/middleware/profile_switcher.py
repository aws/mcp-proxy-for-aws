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

"""Middleware that enables per-call AWS profile overrides via a ``profile`` argument.

Pass ``profile`` as an extra argument on any tool call to route that single request
through a dedicated transport signed with the specified profile's credentials. The
argument is stripped before forwarding to the backend.

Each profile gets its own lazily-created ``StreamableHttpTransport`` and MCP session,
so parallel subagents querying different accounts don't interfere with each other.
"""

import httpx
import logging
import mcp.types as mt
from collections.abc import Sequence
from fastmcp import Client
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool, ToolResult
from mcp_proxy_for_aws.utils import create_transport_with_sigv4
from typing import Any, cast
from typing_extensions import override


logger = logging.getLogger(__name__)


class ProfileOverrideMiddleware(Middleware):
    """Middleware that intercepts ``profile`` on any tool call for per-request AWS identity switching.

    When a tool call includes a ``profile`` argument, the middleware:

    1. Validates the profile against the allowed list
    2. Strips ``profile`` from the arguments
    3. Forwards the call through a dedicated per-profile MCP client

    Each profile gets its own transport and session to the backend so that
    requests signed with different AWS identities don't collide.
    """

    def __init__(
        self,
        allowed_profiles: list[str],
        service: str,
        region: str,
        metadata: dict[str, Any],
        timeout: httpx.Timeout,
        endpoint: str,
    ) -> None:
        """Initialize the middleware with connection and profile configuration."""
        super().__init__()
        self._allowed_profiles = set(allowed_profiles)
        self._endpoint = endpoint
        self._service = service
        self._region = region
        self._metadata = metadata
        self._timeout = timeout
        self._profile_clients: dict[str, Client] = {}

    # ── tool listing ────────────────────────────────────────────────

    @override
    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """Inject ``profile`` into every tool's schema."""
        tools = await call_next(context)

        for tool in tools:
            params = tool.parameters
            if not isinstance(params, dict):
                continue
            if 'properties' not in params:
                params['properties'] = {}
            params['properties']['profile'] = {
                'type': 'string',
                'description': (
                    'AWS CLI profile to sign this request with. Omit to use the default profile.'
                ),
                'enum': sorted(self._allowed_profiles),
            }

        return list(tools)

    # ── tool invocation ─────────────────────────────────────────────

    @override
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Intercept ``profile`` and route through a dedicated per-profile client."""
        arguments = context.message.arguments
        if isinstance(arguments, dict) and 'profile' in arguments:
            profile = arguments['profile']
            return await self._call_with_profile(profile, context, call_next)

        return await call_next(context)

    # ── internals ─────────────────────────────────────────────────

    async def _get_profile_client(self, profile: str) -> Client:
        """Get or create a dedicated MCP client for the given profile.

        Each profile gets its own ``StreamableHttpTransport`` and MCP session
        so that requests signed with different AWS identities don't collide
        on the same backend session.
        """
        if profile not in self._profile_clients:
            logger.info('Creating dedicated connection for profile %s', profile)
            transport = create_transport_with_sigv4(
                self._endpoint,
                self._service,
                self._region,
                self._metadata,
                self._timeout,
                profile,
            )
            client = Client(transport=transport)
            await client.__aenter__()
            self._profile_clients[profile] = client
        return self._profile_clients[profile]

    async def disconnect_profile_clients(self) -> None:
        """Disconnect all per-profile clients. Call during server shutdown."""
        for profile, client in self._profile_clients.items():
            try:
                await client.__aexit__(None, None, None)
            except Exception:
                logger.exception('Failed to disconnect profile client %s', profile)
        self._profile_clients.clear()

    async def _call_with_profile(
        self,
        profile: str,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Forward a tool call through a dedicated per-profile connection."""
        if profile not in self._allowed_profiles:
            allowed = ', '.join(sorted(self._allowed_profiles))
            return ToolResult(
                content=f'Error: profile {profile!r} is not in the allowed list. '
                f'Allowed profiles: {allowed}'
            )

        # Strip profile before forwarding to the backend
        arguments: dict[str, Any] = dict(cast(dict[str, Any], context.message.arguments))
        arguments.pop('profile', None)

        logger.info(
            'Per-call profile override: routing through dedicated connection for %s', profile
        )

        try:
            client = await self._get_profile_client(profile)
        except Exception:
            logger.exception('Failed to create connection for profile %s', profile)
            return ToolResult(
                content=f'Error: failed to create connection for profile {profile!r}. '
                'Check that the profile is configured and credentials are valid.'
            )

        try:
            result = await client.call_tool(context.message.name, arguments)
            return ToolResult(
                content=result.content,
                structured_content=result.structured_content,
                meta=result.meta,
            )
        except Exception:
            logger.exception('Error calling tool via profile %s', profile)
            return ToolResult(
                content=f'Error: tool call failed using profile {profile!r}. '
                'The request could not be completed with the specified profile.'
            )
