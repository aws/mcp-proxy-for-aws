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
    'default-profile',
    'dev-profile',
    'staging-profile',
]


@pytest.fixture
def middleware():
    """Create a ProfileOverrideMiddleware instance."""
    return ProfileOverrideMiddleware(
        allowed_profiles=ALLOWED_PROFILES,
        default_profile='default-profile',
        service='lambda',
        region='us-east-1',
        metadata={'proxy': 'test'},
        timeout=httpx.Timeout(30),
        endpoint='https://test.us-east-1.api.aws/mcp',
        disable_telemetry=False,
        skip_auth=False,
    )


@pytest.fixture
def mock_context():
    """Create a mock MiddlewareContext."""
    return Mock(spec=MiddlewareContext)


class TestOnListTools:
    """Tests for the on_list_tools method."""

    @pytest.mark.asyncio
    async def test_injects_aws_profile_property_into_tool_schemas(self, middleware, mock_context):
        """Auth-requiring tools get a aws_profile property in their schema."""
        tool = Mock()
        tool.name = 'aws___call_aws'
        tool.parameters = {'type': 'object', 'properties': {'arg': {'type': 'string'}}}
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert len(result) == 1
        assert result[0].name == 'aws___call_aws'
        profile_schema = result[0].parameters['properties']['aws_profile']
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
        tool.name = 'aws___call_aws'
        tool.parameters = None
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert len(result) == 1
        assert result[0].parameters is None

    @pytest.mark.asyncio
    async def test_adds_properties_key_when_missing(self, middleware, mock_context):
        """Profile is injected even when the schema has no properties key."""
        tool = Mock()
        tool.name = 'aws___run_script'
        tool.parameters = {'type': 'object'}
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert 'properties' in result[0].parameters
        assert 'aws_profile' in result[0].parameters['properties']

    @pytest.mark.asyncio
    async def test_skips_non_auth_requiring_tools(self, middleware, mock_context):
        """Non-auth tools do not get aws_profile injected."""
        auth_tool = Mock()
        auth_tool.name = 'aws___call_aws'
        auth_tool.parameters = {'type': 'object', 'properties': {'arg': {'type': 'string'}}}

        non_auth_tool = Mock()
        non_auth_tool.name = 'search_documentation'
        non_auth_tool.parameters = {'type': 'object', 'properties': {'query': {'type': 'string'}}}

        call_next = AsyncMock(return_value=[auth_tool, non_auth_tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        assert 'aws_profile' in result[0].parameters['properties']
        assert 'aws_profile' not in result[1].parameters['properties']


class TestOnCallTool:
    """Tests for the on_call_tool method."""

    @pytest.mark.asyncio
    async def test_passes_through_calls_without_aws_profile(self, middleware, mock_context):
        """Tool calls without aws_profile are forwarded unchanged."""
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

    @pytest.mark.asyncio
    async def test_extracts_profile_from_cli_command(self, middleware, mock_context):
        """When calling call_aws with --profile, it is extracted and used as aws_profile."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = 'result'
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_call_result.is_error = False
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {
            'cli_command': 'aws --profile dev-profile sts get-caller-identity'
        }
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            await middleware.on_call_tool(mock_context, call_next)

        mock_client.call_tool.assert_called_once_with(
            'aws___call_aws', {'cli_command': 'aws sts get-caller-identity'}, raise_on_error=False
        )
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_extracts_profile_equals_format_from_cli_command(self, middleware, mock_context):
        """When calling call_aws with --profile=name, it is extracted and used as aws_profile."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = 'result'
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_call_result.is_error = False
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {
            'cli_command': 'aws --profile=dev-profile sts get-caller-identity'
        }
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            await middleware.on_call_tool(mock_context, call_next)

        mock_client.call_tool.assert_called_once_with(
            'aws___call_aws', {'cli_command': 'aws sts get-caller-identity'}, raise_on_error=False
        )
        call_next.assert_not_called()


class TestPerCallProfileOverride:
    """Tests for the profile per-call override path."""

    @pytest.mark.asyncio
    async def test_profile_override_disallowed(self, middleware, mock_context):
        """Disallowed profile raises ToolError."""
        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'evil-profile'}
        call_next = AsyncMock()

        with pytest.raises(ToolError, match='not in the allowed list'):
            await middleware.on_call_tool(mock_context, call_next)

        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_profile_override_strips_aws_profile_arg(self, middleware, mock_context):
        """aws_profile is stripped before forwarding to the backend."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = 'result'
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_call_result.is_error = False
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            await middleware.on_call_tool(mock_context, call_next)

        mock_client.call_tool.assert_called_once_with(
            'aws___call_aws', {'arg': 'value'}, raise_on_error=False
        )
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_default_profile_routes_through_call_next(self, middleware, mock_context):
        """When aws_profile matches the default, route through normal path."""
        mock_context.message = Mock()
        mock_context.message.name = 'some_tool'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'default-profile'}
        expected_result = Mock()
        call_next = AsyncMock(return_value=expected_result)

        result = await middleware.on_call_tool(mock_context, call_next)

        assert result == expected_result
        call_next.assert_called_once_with(mock_context)
        # aws_profile should be stripped from arguments
        assert 'aws_profile' not in mock_context.message.arguments

    @pytest.mark.asyncio
    async def test_profile_override_propagates_is_error(self, middleware, mock_context):
        """Backend isError=True is propagated as a ToolError."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_content_block = MagicMock()
        mock_content_block.text = 'backend error message'
        mock_call_result.content = [mock_content_block]
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_call_result.is_error = True
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError, match='backend error message'):
                await middleware.on_call_tool(mock_context, call_next)

    @pytest.mark.asyncio
    async def test_profile_override_connection_failure(self, middleware, mock_context):
        """Connection failure raises ToolError with sanitized message."""
        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(
            middleware, '_get_profile_client', side_effect=Exception('connection refused')
        ):
            with pytest.raises(ToolError, match='Failed to create connection') as exc_info:
                await middleware.on_call_tool(mock_context, call_next)

        assert 'connection refused' not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_profile_override_tool_call_failure(self, middleware, mock_context):
        """Tool call failure raises ToolError with sanitized message."""
        mock_client = AsyncMock()
        mock_client.call_tool.side_effect = Exception('backend error')

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError, match='Tool call failed') as exc_info:
                await middleware.on_call_tool(mock_context, call_next)

        assert 'backend error' not in str(exc_info.value)


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

        with (
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.create_transport_with_sigv4',
                return_value=mock_transport,
            ),
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.Client',
                return_value=mock_client,
            ),
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


class TestFix1OnlyAuthToolsGetInjection:
    """Fix #1: aws_profile only injected on auth-requiring tools."""

    @pytest.mark.asyncio
    async def test_all_auth_tools_get_injection(self, middleware, mock_context):
        """All four auth-requiring tools get aws_profile."""
        tools = []
        for name in [
            'aws___call_aws',
            'aws___run_script',
            'aws___get_presigned_url',
            'aws___get_tasks',
            'aws___suggest_aws_commands',
        ]:
            tool = Mock()
            tool.name = name
            tool.parameters = {'type': 'object', 'properties': {}}
            tools.append(tool)
        call_next = AsyncMock(return_value=tools)

        result = await middleware.on_list_tools(mock_context, call_next)

        for tool in result:
            assert 'aws_profile' in tool.parameters['properties'], (
                f'{tool.name} should have aws_profile'
            )

    @pytest.mark.asyncio
    async def test_non_auth_tools_never_get_injection(self, middleware, mock_context):
        """Non-auth tools like search_documentation, list_regions, etc. are untouched."""
        tools = []
        for name in [
            'search_documentation',
            'read_documentation',
            'list_regions',
            'recommend',
            'retrieve_skill',
            'get_regional_availability',
        ]:
            tool = Mock()
            tool.name = name
            tool.parameters = {'type': 'object', 'properties': {'q': {'type': 'string'}}}
            tools.append(tool)
        call_next = AsyncMock(return_value=tools)

        result = await middleware.on_list_tools(mock_context, call_next)

        for tool in result:
            assert 'aws_profile' not in tool.parameters['properties'], (
                f'{tool.name} should NOT have aws_profile'
            )


class TestFix3DefaultProfileInEnum:
    """Fix #3: Default profile included in enum and routes through call_next."""

    @pytest.mark.asyncio
    async def test_default_profile_appears_in_enum(self, middleware, mock_context):
        """The default profile is included in the schema enum."""
        tool = Mock()
        tool.name = 'aws___call_aws'
        tool.parameters = {'type': 'object', 'properties': {}}
        call_next = AsyncMock(return_value=[tool])

        result = await middleware.on_list_tools(mock_context, call_next)

        enum_values = result[0].parameters['properties']['aws_profile']['enum']
        assert 'default-profile' in enum_values

    @pytest.mark.asyncio
    async def test_default_profile_does_not_create_separate_client(self, middleware, mock_context):
        """Passing the default profile does not create a dedicated client."""
        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {
            'cli_command': 'aws sts get-caller-identity',
            'aws_profile': 'default-profile',
        }
        expected_result = Mock()
        call_next = AsyncMock(return_value=expected_result)

        await middleware.on_call_tool(mock_context, call_next)

        # No profile client should have been created
        assert 'default-profile' not in middleware._profile_clients

    @pytest.mark.asyncio
    async def test_default_profile_strips_param_before_call_next(self, middleware, mock_context):
        """aws_profile is stripped even when routing through default path."""
        mock_context.message = Mock()
        mock_context.message.arguments = {
            'cli_command': 'aws s3 ls',
            'aws_profile': 'default-profile',
        }
        mock_context.message.name = 'aws___call_aws'
        call_next = AsyncMock(return_value=Mock())

        await middleware.on_call_tool(mock_context, call_next)

        # The arguments passed to call_next should not contain aws_profile
        assert 'aws_profile' not in mock_context.message.arguments
        assert 'cli_command' in mock_context.message.arguments


class TestFix4RetryExceptionChaining:
    """Fix #4: Exception chain preserved so RetryMiddleware can retry."""

    @pytest.mark.asyncio
    async def test_tool_call_failure_preserves_cause(self, middleware, mock_context):
        """ToolError from tool call failure has __cause__ set to original exception."""
        mock_client = AsyncMock()
        original_error = ConnectionError('connection reset')
        mock_client.call_tool.side_effect = original_error

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError) as exc_info:
                await middleware.on_call_tool(mock_context, call_next)

        assert exc_info.value.__cause__ is original_error

    @pytest.mark.asyncio
    async def test_connection_failure_preserves_cause(self, middleware, mock_context):
        """ToolError from connection failure has __cause__ set to original exception."""
        original_error = TimeoutError('connect timed out')

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'arg': 'value', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', side_effect=original_error):
            with pytest.raises(ToolError) as exc_info:
                await middleware.on_call_tool(mock_context, call_next)

        assert exc_info.value.__cause__ is original_error


class TestFix5IsErrorPropagation:
    """Fix #5: Backend isError=True is propagated as ToolError."""

    @pytest.mark.asyncio
    async def test_is_error_true_raises_tool_error(self, middleware, mock_context):
        """When backend returns isError=True, a ToolError is raised."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_content_block = MagicMock()
        mock_content_block.text = 'Access denied for this operation'
        mock_call_result.content = [mock_content_block]
        mock_call_result.is_error = True
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'cli_command': 'aws s3 ls', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError, match='Access denied for this operation'):
                await middleware.on_call_tool(mock_context, call_next)

    @pytest.mark.asyncio
    async def test_is_error_false_returns_result(self, middleware, mock_context):
        """When backend returns isError=False, a normal ToolResult is returned."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = 'success'
        mock_call_result.structured_content = None
        mock_call_result.meta = None
        mock_call_result.is_error = False
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'cli_command': 'aws s3 ls', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            result = await middleware.on_call_tool(mock_context, call_next)

        assert result.content is not None


class TestRaiseOnErrorFalseEnforced:
    """Verify raise_on_error=False is critical for error extraction logic."""

    @pytest.mark.asyncio
    async def test_raise_on_error_false_allows_is_error_extraction(self, middleware, mock_context):
        """If raise_on_error were True, backend errors would bypass our extraction logic.

        This test confirms the middleware correctly passes raise_on_error=False
        and handles the is_error field from the result object.
        """
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_content_block = MagicMock()
        mock_content_block.text = 'ThrottlingException: Rate exceeded'
        mock_call_result.content = [mock_content_block]
        mock_call_result.is_error = True
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'cli_command': 'aws s3 ls', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            with pytest.raises(ToolError, match='ThrottlingException'):
                await middleware.on_call_tool(mock_context, call_next)

        # Confirm raise_on_error=False was passed
        mock_client.call_tool.assert_called_once_with(
            'aws___call_aws', {'cli_command': 'aws s3 ls'}, raise_on_error=False
        )


class TestStructuredContentAndMetaPassthrough:
    """Verify structured_content and meta are propagated on success."""

    @pytest.mark.asyncio
    async def test_non_none_structured_content_and_meta_propagated(self, middleware, mock_context):
        """Non-None structured_content and meta values are passed through to ToolResult."""
        mock_client = AsyncMock()
        mock_call_result = MagicMock()
        mock_call_result.content = [MagicMock(text='ok')]
        mock_call_result.structured_content = {'key': 'value', 'nested': [1, 2, 3]}
        mock_call_result.meta = {'request_id': 'abc-123', 'latency_ms': 42}
        mock_call_result.is_error = False
        mock_client.call_tool.return_value = mock_call_result

        mock_context.message = Mock()
        mock_context.message.name = 'aws___call_aws'
        mock_context.message.arguments = {'cli_command': 'aws s3 ls', 'aws_profile': 'dev-profile'}
        call_next = AsyncMock()

        with patch.object(middleware, '_get_profile_client', return_value=mock_client):
            result = await middleware.on_call_tool(mock_context, call_next)

        assert result.structured_content == {'key': 'value', 'nested': [1, 2, 3]}
        assert result.meta == {'request_id': 'abc-123', 'latency_ms': 42}


class TestAwsProfileAlreadyInSchema:
    """Verify warning path when tool already defines aws_profile."""

    @pytest.mark.asyncio
    async def test_existing_aws_profile_is_overwritten_with_warning(
        self, middleware, mock_context, caplog
    ):
        """Tool with pre-existing aws_profile gets it overwritten and a warning is logged."""
        tool = Mock()
        tool.name = 'aws___call_aws'
        tool.parameters = {
            'type': 'object',
            'properties': {
                'cli_command': {'type': 'string'},
                'aws_profile': {
                    'type': 'string',
                    'description': 'Original backend definition',
                    'enum': ['old-profile'],
                },
            },
        }
        call_next = AsyncMock(return_value=[tool])

        import logging

        with caplog.at_level(logging.WARNING):
            result = await middleware.on_list_tools(mock_context, call_next)

        # The middleware's version should overwrite the backend's
        profile_schema = result[0].parameters['properties']['aws_profile']
        assert profile_schema['enum'] == sorted(ALLOWED_PROFILES)
        assert 'shadowing the backend definition' in caplog.text


class TestLockWithDeterministicSynchronization:
    """Deterministic lock test using asyncio.Event instead of sleep."""

    @pytest.mark.asyncio
    async def test_lock_prevents_duplicate_creation_deterministic(self, middleware):
        """Concurrent calls for the same profile only create one client (event-based)."""
        creation_count = 0
        gate = asyncio.Event()
        mock_client = AsyncMock()

        async def slow_aenter(*args, **kwargs):
            nonlocal creation_count
            creation_count += 1
            # Wait for the gate — simulates slow connection setup
            await gate.wait()
            return mock_client

        mock_client.__aenter__ = slow_aenter

        mock_transport = Mock()

        with (
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.create_transport_with_sigv4',
                return_value=mock_transport,
            ),
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.Client',
                return_value=mock_client,
            ),
        ):
            # Start 3 concurrent requests for the same profile
            tasks = [
                asyncio.create_task(middleware._get_profile_client('staging-profile'))
                for _ in range(3)
            ]
            # Let the event loop schedule all tasks
            await asyncio.sleep(0)
            # Release the gate
            gate.set()
            results = await asyncio.gather(*tasks)

        assert all(r is mock_client for r in results)
        assert creation_count == 1


class TestRetryMiddlewareIntegration:
    """Integration test: ProfileOverrideMiddleware + RetryMiddleware chained together."""

    @pytest.mark.asyncio
    async def test_retry_middleware_recognizes_connection_error_cause(self):
        """RetryMiddleware._should_retry returns True for ToolError from ConnectionError."""
        from fastmcp.server.middleware.error_handling import RetryMiddleware

        retry_mw = RetryMiddleware(max_retries=2)

        # Simulate what ProfileOverrideMiddleware does: raise ToolError(...) from ConnectionError
        original = ConnectionError('connection reset by peer')
        tool_error = ToolError("Tool call failed using profile 'dev'.")
        tool_error.__cause__ = original

        assert retry_mw._should_retry(tool_error) is True

    @pytest.mark.asyncio
    async def test_retry_middleware_recognizes_timeout_error_cause(self):
        """RetryMiddleware._should_retry returns True for ToolError from TimeoutError."""
        from fastmcp.server.middleware.error_handling import RetryMiddleware

        retry_mw = RetryMiddleware(max_retries=2)

        original = TimeoutError('connect timed out')
        tool_error = ToolError("Failed to create connection for profile 'dev'.")
        tool_error.__cause__ = original

        assert retry_mw._should_retry(tool_error) is True

    @pytest.mark.asyncio
    async def test_retry_middleware_does_not_retry_non_transient_cause(self):
        """RetryMiddleware._should_retry returns False for ToolError from ValueError."""
        from fastmcp.server.middleware.error_handling import RetryMiddleware

        retry_mw = RetryMiddleware(max_retries=2)

        original = ValueError('invalid profile name')
        tool_error = ToolError('Profile not in allowed list.')
        tool_error.__cause__ = original

        assert retry_mw._should_retry(tool_error) is False

    @pytest.mark.asyncio
    async def test_retry_middleware_does_not_retry_tool_error_without_cause(self):
        """RetryMiddleware._should_retry returns False for ToolError with no __cause__."""
        from fastmcp.server.middleware.error_handling import RetryMiddleware

        retry_mw = RetryMiddleware(max_retries=2)

        tool_error = ToolError("Profile 'evil' is not in the allowed list.")
        # No __cause__ set (e.g., disallowed profile validation error)

        assert retry_mw._should_retry(tool_error) is False


class TestNonAuthToolIgnoresAwsProfile:
    """Verify aws_profile on non-auth tools is stripped and routed normally."""

    @pytest.mark.asyncio
    async def test_non_auth_tool_with_aws_profile_strips_and_passes_through(
        self, middleware, mock_context
    ):
        """Non-auth tool with aws_profile has it stripped and routes through call_next."""
        mock_context.message = Mock()
        mock_context.message.name = 'search_documentation'
        mock_context.message.arguments = {
            'query': 'lambda cold starts',
            'aws_profile': 'dev-profile',
        }
        expected_result = Mock()
        call_next = AsyncMock(return_value=expected_result)

        result = await middleware.on_call_tool(mock_context, call_next)

        assert result == expected_result
        call_next.assert_called_once_with(mock_context)
        # aws_profile should be stripped
        assert 'aws_profile' not in mock_context.message.arguments
        # Original args preserved
        assert mock_context.message.arguments['query'] == 'lambda cold starts'

    @pytest.mark.asyncio
    async def test_non_auth_tool_does_not_create_profile_client(self, middleware, mock_context):
        """Non-auth tool with aws_profile does not create a dedicated client."""
        mock_context.message = Mock()
        mock_context.message.name = 'list_regions'
        mock_context.message.arguments = {'aws_profile': 'staging-profile'}
        call_next = AsyncMock(return_value=Mock())

        await middleware.on_call_tool(mock_context, call_next)

        assert 'staging-profile' not in middleware._profile_clients


class TestProfileClientTransportParams:
    """Verify all constructor params are forwarded to create_transport_with_sigv4."""

    @pytest.mark.asyncio
    async def test_all_params_forwarded_to_transport_factory(self, mock_context):
        """_get_profile_client passes all config params to create_transport_with_sigv4."""
        mw = ProfileOverrideMiddleware(
            allowed_profiles=['default-profile', 'dev-profile'],
            default_profile='default-profile',
            service='bedrock-agentcore',
            region='eu-west-1',
            metadata={'AWS_REGION': 'eu-west-1', 'custom': 'val'},
            timeout=httpx.Timeout(60),
            endpoint='https://bedrock-agentcore.eu-west-1.api.aws/mcp',
            disable_telemetry=True,
            skip_auth=True,
        )

        mock_transport = Mock()
        mock_client = AsyncMock()

        with (
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.create_transport_with_sigv4',
                return_value=mock_transport,
            ) as mock_create,
            patch(
                'mcp_proxy_for_aws.middleware.profile_switcher.Client',
                return_value=mock_client,
            ),
        ):
            await mw._get_profile_client('dev-profile')

        mock_create.assert_called_once_with(
            'https://bedrock-agentcore.eu-west-1.api.aws/mcp',
            'bedrock-agentcore',
            'eu-west-1',
            {'AWS_REGION': 'eu-west-1', 'custom': 'val'},
            httpx.Timeout(60),
            'dev-profile',
            True,
            True,
        )
