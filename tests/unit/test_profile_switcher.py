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

"""Tests for the ProfileOverrideMiddleware."""

import asyncio
import httpx
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from mcp_proxy_for_aws.middleware.profile_switcher import ProfileOverrideMiddleware
from unittest.mock import AsyncMock, MagicMock, Mock, patch


ALLOWED_PROFILES = [
    'dev-profile',
    'staging-profile',
]


@pytest.fixture
def middleware():
    """Create a ProfileOverrideMiddleware instance."""
    return ProfileOverrideMiddleware(
        allowed_profiles=ALLOWED_PROFILES,
        service='lambda',
        region='us-east-1',
        metadata={'proxy': 'test'},
        timeout=httpx.Timeout(30),
        endpoint='https://test.us-east-1.api.aws/mcp',
    )


@pytest.fixture
def mock_context():
    """Create a mock MiddlewareContext."""
    return Mock(spec=MiddlewareContext)


class TestOnListTools:
    """Tests for the on_list_tools method."""

    @pytest.mark.asyncio
    async def test_injects_profile_property_into_tool_schemas(self, middleware, mock_context):
        """Every proxied tool gets a profile property in its schema."""
        tool = Mock()
        tool.name = 'some_tool'
        tool.parameters = {'type': 'object', 'properties': {'arg': {'type': 'string'}}}
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert len(result) == 1
        assert result[0].name == 'some_tool'
        profile_schema = result[0].parameters['properties']['mcp_proxy_aws_profile']
        assert profile_schema['type'] == 'string'
        assert 'AWS CLI profile' in profile_schema['description']
        assert profile_schema['enum'] == sorted(ALLOWED_PROFILES)
        call_next.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_handles_empty_tool_list(self, middleware, mock_context):
        """Empty tool list is returned as-is."""
        call_next = AsyncMock(return_value=[])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_skips_tool_with_non_dict_parameters(self, middleware, mock_context):
        """Tools whose parameters are not a dict are left unchanged."""
        tool = Mock()
        tool.name = 'odd_tool'
        tool.parameters = None
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert len(result) == 1
        assert result[0].parameters is None

    @pytest.mark.asyncio
    async def test_adds_properties_key_when_missing(self, middleware, mock_context):
        """Profile is injected even when the schema has no properties key."""
        tool = Mock()
        tool.name = 'bare_tool'
        tool.parameters = {'type': 'object'}
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert 'properties' in result[0].parameters
        assert 'mcp_proxy_aws_profile' in result[0].parameters['properties']


class TestOnCallTool:
    """Tests for the on_call_tool method."""

    @pytest.mark.asyncio
    async def test_passes_through_calls_without_profile(self, middleware, mock_context):
        """Tool calls without profile are forwarded unchanged."""
        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value'}
        expected_result = Mock()
        call_next = AsyncMock(return_value=expected_result)

        result = await middleware.on_call_tool(mock_context, call_next)

        assert result == expected_result
        call_next.assert_called_once_with(mock_context)

    @pytest.mark.asyncio
    async def test_passes_through_calls_with_none_arguments(self, middleware, mock_context):
        """Tool calls with None arguments are forwarded unchanged."""
        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = None
        expected_result = Mock()
        call_next = AsyncMock(return_value=expected_result)

        result = await middleware.on_call_tool(mock_context, call_next)

        assert result == expected_result
        call_next.assert_called_once_with(mock_context)


class TestPerCallProfileOverride:
    """Tests for the profile per-call override path."""

    @pytest.mark.asyncio
    async def test_profile_override_disallowed(self, middleware, mock_context):
        """Profile with a disallowed profile raises ToolError."""
        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value', 'mcp_proxy_aws_profile': 'evil-profile'}
        call_next = AsyncMock()

        with pytest.raises(ToolError, match='not in the allowed list'):
            await middleware.on_call_tool(mock_context, call_next)

        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_profile_override_strips_profile_arg(self, middleware, mock_context):
        """Profile is stripped before forwarding to the backend."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = 'result'
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value', 'mcp_proxy_aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            await middleware.on_call_tool(mock_context, call_next)

        mock_client.call_tool.assert_called_once_with('some_tool', {'arg': 'value'})
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_profile_override_connection_failure(self, middleware, mock_context):
        """Connection failure raises ToolError with sanitized message."""
        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value', 'mcp_proxy_aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(
            middleware, '_get_profile_client', side_effect=Exception('connection refused')
        ):
            with pytest.raises(ToolError, match='Failed to create connection'):
                await middleware.on_call_tool(mock_context, call_next)

    @pytest.mark.asyncio
    async def test_profile_override_tool_call_failure(self, middleware, mock_context):
        """Tool call failure raises ToolError with sanitized message."""
        mock_client = AsyncMock()
        mock_client.call_tool.side_effect = Exception('backend error')

        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value', 'mcp_proxy_aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError, match='Tool call failed'):
                await middleware.on_call_tool(mock_context, call_next)


class TestGetProfileClient:
    """Tests for the _get_profile_client method."""

    @pytest.mark.asyncio
    async def test_lock_prevents_duplicate_client_creation(self, middleware):
        """Concurrent calls for the same profile only create one client."""
        call_count = 0
        mock_client = AsyncMock()

        original_aenter = mock_client.__aenter__

        async def slow_aenter(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            return await original_aenter(*args, **kwargs)

        mock_client.__aenter__ = slow_aenter

        mock_transport = Mock()

        with patch(
            'mcp_proxy_for_aws.middleware.profile_switcher.create_transport_with_sigv4',
            return_value=mock_transport,
        ), patch(
            'mcp_proxy_for_aws.middleware.profile_switcher.Client',
            return_value=mock_client,
        ):
            results = await asyncio.gather(
                middleware._get_profile_client('dev-profile'),
                middleware._get_profile_client('dev-profile'),
                middleware._get_profile_client('dev-profile'),
            )

        # All calls return the same client
        assert all(r is mock_client for r in results)
        # Client was only created once despite 3 concurrent calls
        assert call_count == 1


class TestDisconnectProfileClients:
    """Tests for the disconnect_profile_clients method."""

    @pytest.mark.asyncio
    async def test_disconnects_all_clients(self, middleware):
        """All cached profile clients are closed and the cache is cleared."""
        client_a = AsyncMock()
        client_b = AsyncMock()
        middleware._profile_clients = {'profile-a': client_a, 'profile-b': client_b}

        await middleware.disconnect_profile_clients()

        client_a.__aexit__.assert_called_once_with(None, None, None)
        client_b.__aexit__.assert_called_once_with(None, None, None)
        assert middleware._profile_clients == {}

    @pytest.mark.asyncio
    async def test_continues_on_client_error(self, middleware):
        """A failing client does not prevent other clients from disconnecting."""
        client_good = AsyncMock()
        client_bad = AsyncMock()
        client_bad.__aexit__.side_effect = Exception('disconnect failed')
        middleware._profile_clients = {'bad': client_bad, 'good': client_good}

        await middleware.disconnect_profile_clients()

        client_bad.__aexit__.assert_called_once_with(None, None, None)
        client_good.__aexit__.assert_called_once_with(None, None, None)
        assert middleware._profile_clients == {}
