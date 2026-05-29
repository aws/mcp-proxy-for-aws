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

"""Middleware that enables per-call AWS profile overrides via a ``aws_profile`` argument.

Pass ``aws_profile`` as an extra argument on any auth-requiring tool call to route
that single request through a dedicated transport signed with the specified profile's
credentials. The argument is stripped before forwarding to the backend.

Each non-default profile gets its own lazily-created ``StreamableHttpTransport`` and MCP
session, so parallel subagents querying different accounts don't interfere with each other.
When the default profile is specified explicitly, the call is routed through the normal
middleware chain (no duplicate connection).
"""

import asyncio
import copy
import httpx
import logging
import mcp.types as mt
from collections.abc import Sequence
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult
from mcp_proxy_for_aws.utils import create_transport_with_sigv4
from typing import Any, cast
from typing_extensions import override


logger = logging.getLogger(__name__)


class ProfileOverrideMiddleware(Middleware):
    """Middleware that intercepts ``aws_profile`` on any tool call for per-request AWS identity switching.

    When a tool call includes a ``aws_profile`` argument, the middleware:

    1. Validates the profile against the allowed list
    2. Strips ``aws_profile`` from the arguments
    3. Forwards the call through a dedicated per-profile MCP client

    Each profile gets its own transport and session to the backend so that
    requests signed with different AWS identities don't collide.
    """

    def __init__(
        self,
        allowed_profiles: list[str],
        default_profile: str,
        service: str,
        region: str,
        metadata: dict[str, Any],
        timeout: httpx.Timeout,
        endpoint: str,
        disable_telemetry: bool = False,
        skip_auth: bool = False,
    ) -> None:
        """Initialize the middleware with connection and profile configuration."""
        super().__init__()
        self._allowed_profiles = set(allowed_profiles)
        self._default_profile = default_profile
        self._endpoint = endpoint
        self._service = service
        self._region = region
        self._metadata = metadata
        self._timeout = timeout
        self._disable_telemetry = disable_telemetry
        self._skip_auth = skip_auth
        self._profile_clients: dict[str, Client] = {}
        self._lock = asyncio.Lock()

    # Tools that require AWS authentication and support profile switching
    AUTH_REQUIRING_TOOLS = {
        'aws___call_aws',
        'aws___run_script',
        'aws___get_presigned_url',
        'aws___get_tasks',
        'aws___suggest_aws_commands',
    }

    # ── tool listing ────────────────────────────────────────────────

    @override
    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """Inject ``aws_profile`` into auth-requiring tools' schemas only."""
        tools = await call_next(context)

        for tool in tools:
            if tool.name not in self.AUTH_REQUIRING_TOOLS:
                continue
            if not isinstance(tool.parameters, dict):
                continue
            # Deep-copy to avoid mutating upstream cached/shared dicts
            params = copy.deepcopy(tool.parameters)
            if 'properties' not in params:
                params['properties'] = {}
            if 'aws_profile' in params['properties']:
                logger.warning(
                    'Tool %r already defines a "aws_profile" parameter; '
                    'the middleware override is shadowing the backend definition.',
                    tool.name,
                )
            params['properties']['aws_profile'] = {
                'type': 'string',
                'description': (
                    'AWS CLI profile to sign this request with. '
                    'Available profiles: ' + ', '.join(sorted(self._allowed_profiles)) + '.'
                ),
                'enum': sorted(self._allowed_profiles),
            }
            tool.parameters = params

        return list(tools)

    # ── tool invocation ─────────────────────────────────────────────

    @override
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Intercept ``aws_profile`` and route through a dedicated per-profile client."""
        arguments = context.message.arguments
        if isinstance(arguments, dict) and 'aws_profile' in arguments:
            # Only process aws_profile for auth-requiring tools.
            # If an agent hallucinates the parameter on a non-auth tool,
            # strip it silently and route through the normal path.
            if context.message.name not in self.AUTH_REQUIRING_TOOLS:
                logger.warning('Ignoring aws_profile on non-auth tool %r', context.message.name)
                arguments.pop('aws_profile', None)
                return await call_next(context)
            profile = arguments['aws_profile']
            return await self._call_with_profile(profile, context, call_next)

        return await call_next(context)

    # ── internals ─────────────────────────────────────────────────

    async def _get_profile_client(self, profile: str) -> Client:
        """Get or create a dedicated MCP client for the given profile.

        Each profile gets its own ``StreamableHttpTransport`` and MCP session
        so that requests signed with different AWS identities don't collide
        on the same backend session.
        """
        async with self._lock:
            if profile not in self._profile_clients:
                logger.info('Creating dedicated connection for profile %s', profile)
                transport = create_transport_with_sigv4(
                    self._endpoint,
                    self._service,
                    self._region,
                    self._metadata,
                    self._timeout,
                    profile,
                    self._disable_telemetry,
                    self._skip_auth,
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
            raise ToolError(
                f'Profile {profile!r} is not in the allowed list. Allowed profiles: {allowed}'
            )

        # Strip aws_profile before forwarding to the backend
        arguments: dict[str, Any] = dict(cast(dict[str, Any], context.message.arguments))
        arguments.pop('aws_profile', None)

        # If it's the default profile, route through the normal middleware chain.
        # This reuses the existing default client (no duplicate connection)
        # and preserves retry middleware behavior.
        if profile == self._default_profile:
            context.message.arguments = arguments
            return await call_next(context)

        logger.info(
            'Per-call profile override: routing through dedicated connection for %s', profile
        )

        try:
            client = await self._get_profile_client(profile)
        except Exception as e:
            logger.exception('Failed to create connection for profile %s', profile)
            raise ToolError(
                f'Failed to create connection for profile {profile!r}. '
                'Check that the profile is configured and credentials are valid.'
            ) from e

        try:
            result = await client.call_tool(context.message.name, arguments, raise_on_error=False)
            if result.is_error:
                # Propagate the backend error message to the agent
                error_text = ''
                for block in result.content:
                    if hasattr(block, 'text'):
                        error_text += block.text  # type: ignore[union-attr]
                raise ToolError(error_text or f'Tool call failed using profile {profile!r}.')
            return ToolResult(
                content=result.content,
                structured_content=result.structured_content,
                meta=result.meta,
            )
        except ToolError:
            raise
        except Exception as e:
            logger.exception('Error calling tool via profile %s', profile)
            raise ToolError(
                f'Tool call failed using profile {profile!r}. '
                'The request could not be completed with the specified profile.'
            ) from e
