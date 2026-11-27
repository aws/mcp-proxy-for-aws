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

"""Unit tests for AWS session caching and invalidation in sigv4_helper."""

import asyncio
import httpx2
import os
import pytest
import threading
from botocore.credentials import (
    Credentials,
    DeferredRefreshableCredentials,
    RefreshableCredentials,
)
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from mcp_proxy_for_aws.sigv4_helper import (
    _handle_error_response,
    _sign_request_hook,
    create_sigv4_client,
)
from pathlib import Path
from unittest.mock import MagicMock, patch


def _make_session(access_key: str = 'AKIAEXAMPLE1', token: str = 'token-1') -> MagicMock:
    """Create a mock boto3 session returning static botocore Credentials."""
    session = MagicMock()
    session.get_credentials.return_value = Credentials(
        access_key=access_key,
        secret_key='secret-key',
        token=token,
    )
    return session


def _extract_access_key(request: httpx2.Request) -> str:
    """Extract the AWS access key ID from a signed request's Authorization header."""
    return request.headers['Authorization'].split('Credential=')[1].split('/')[0]


def _bump_mtime(path: Path, delta_seconds: float = 10.0) -> None:
    """Advance a path's mtime deterministically to avoid coarse filesystem clock ticks."""
    st = path.stat()
    new_mtime = st.st_mtime + delta_seconds
    os.utime(path, (st.st_atime, new_mtime))


@pytest.fixture(autouse=True)
def isolated_aws_fs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point AWS config, credentials, and cache paths at an isolated temporary directory."""
    aws_dir = tmp_path / '.aws'
    (aws_dir / 'sso' / 'cache').mkdir(parents=True)
    (aws_dir / 'cli' / 'cache').mkdir(parents=True)
    (aws_dir / 'login' / 'cache').mkdir(parents=True)
    (aws_dir / 'config').write_text('[default]\nregion = us-east-1\n', encoding='utf-8')
    (aws_dir / 'credentials').write_text(
        '[default]\naws_access_key_id = AKIA1\naws_secret_access_key = secret1\n',
        encoding='utf-8',
    )

    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('USERPROFILE', str(tmp_path))
    for var in (
        'AWS_CONFIG_FILE',
        'AWS_SHARED_CREDENTIALS_FILE',
        'AWS_LOGIN_CACHE_DIRECTORY',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_SECURITY_TOKEN',
        'AWS_CREDENTIAL_EXPIRATION',
        'AWS_ACCOUNT_ID',
        'AWS_PROFILE',
        'AWS_DEFAULT_PROFILE',
        'AWS_ROLE_ARN',
        'AWS_WEB_IDENTITY_TOKEN_FILE',
        'AWS_ROLE_SESSION_NAME',
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
        'AWS_CONTAINER_CREDENTIALS_FULL_URI',
        'AWS_CONTAINER_AUTHORIZATION_TOKEN',
        'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
        'AWS_REGION',
        'AWS_DEFAULT_REGION',
    ):
        monkeypatch.delenv(var, raising=False)

    return tmp_path


class TestSessionReuse:
    """Verify sessions and deferred credentials are reused across requests."""

    @pytest.mark.asyncio
    async def test_reuses_session_across_requests_for_same_profile(self):
        """Repeated requests with unchanged disk/env reuse the cached boto3 session."""
        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            return_value=_make_session('AKIACACHED', 'tok-cached'),
        ) as mock_create:
            for _ in range(4):
                request = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
                await _sign_request_hook('us-east-1', 'execute-api', 'sso-profile', False, request)
                assert _extract_access_key(request) == 'AKIACACHED'

            mock_create.assert_called_once_with('sso-profile')

    @pytest.mark.asyncio
    async def test_deferred_refreshable_credentials_fetched_once_across_requests(self):
        """SSO-style DeferredRefreshableCredentials fetches role credentials once across requests."""
        fetch_calls = 0

        def fetch_role_credentials():
            nonlocal fetch_calls
            fetch_calls += 1
            expiry = datetime.now(UTC) + timedelta(hours=1)
            return {
                'access_key': f'ASIASSO{fetch_calls}',
                'secret_key': f'sso-secret-{fetch_calls}',
                'token': f'sso-token-{fetch_calls}',
                'expiry_time': expiry.isoformat(),
            }

        def build_sso_session(_profile: str | None = None):
            session = MagicMock()
            session.get_credentials.return_value = DeferredRefreshableCredentials(
                refresh_using=fetch_role_credentials,
                method='sso',
            )
            return session

        sent_requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            sent_requests.append(request)
            return httpx2.Response(200, json={'jsonrpc': '2.0', 'id': 1, 'result': {}})

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=build_sso_session,
        ) as mock_create:
            client = create_sigv4_client(
                service='execute-api',
                region='eu-west-1',
                profile='sso-profile',
                transport=httpx2.MockTransport(handler),
            )
            async with client:
                for i in range(5):
                    await client.post(
                        'https://example.com/mcp',
                        json={'jsonrpc': '2.0', 'id': i, 'method': 'ping'},
                    )

        assert mock_create.call_count == 1
        assert fetch_calls == 1
        assert len(sent_requests) == 5
        assert all(_extract_access_key(req) == 'ASIASSO1' for req in sent_requests)

    @pytest.mark.asyncio
    async def test_caches_independently_per_profile(self):
        """Different profiles maintain isolated cached sessions."""
        sessions = {
            'profile-a': _make_session('AKIA_A', 'tok-a'),
            'profile-b': _make_session('AKIA_B', 'tok-b'),
        }

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=lambda p: sessions[p],
        ) as mock_create:
            for profile, expected_key in [
                ('profile-a', 'AKIA_A'),
                ('profile-b', 'AKIA_B'),
                ('profile-a', 'AKIA_A'),
                ('profile-b', 'AKIA_B'),
            ]:
                req = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
                await _sign_request_hook('us-east-1', 'execute-api', profile, False, req)
                assert _extract_access_key(req) == expected_key

        assert mock_create.call_count == 2


class TestDiskInvalidation:
    """Verify disk config, credentials, and cache changes trigger immediate rebuilds."""

    @pytest.mark.asyncio
    async def test_rebuilds_when_aws_config_changes(self, isolated_aws_fs: Path):
        """Modifying ~/.aws/config forces a fresh session on the very next request."""
        sessions = [_make_session('AKIA_OLD'), _make_session('AKIA_NEW')]
        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'AKIA_OLD'

            config_file = isolated_aws_fs / '.aws' / 'config'
            config_file.write_text('[default]\nregion = eu-west-1\n', encoding='utf-8')
            _bump_mtime(config_file)

            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'AKIA_NEW'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_rebuilds_when_aws_credentials_file_changes(self, isolated_aws_fs: Path):
        """Modifying ~/.aws/credentials forces a fresh session on the next request."""
        sessions = [_make_session('AKIA_OLD'), _make_session('AKIA_NEW')]
        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req1)
            assert _extract_access_key(req1) == 'AKIA_OLD'

            creds_file = isolated_aws_fs / '.aws' / 'credentials'
            creds_file.write_text(
                '[default]\naws_access_key_id = AKIA2\naws_secret_access_key = secret2\n',
                encoding='utf-8',
            )
            _bump_mtime(creds_file)

            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req2)
            assert _extract_access_key(req2) == 'AKIA_NEW'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_rebuilds_when_custom_config_or_credentials_files_change(
        self, isolated_aws_fs: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Custom AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE paths are tracked."""
        custom_config = isolated_aws_fs / 'custom_config'
        custom_creds = isolated_aws_fs / 'custom_creds'
        custom_config.write_text('[default]\nregion = us-east-1\n', encoding='utf-8')
        custom_creds.write_text('[default]\naws_access_key_id = AKIA1\n', encoding='utf-8')
        monkeypatch.setenv('AWS_CONFIG_FILE', str(custom_config))
        monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(custom_creds))

        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2'), _make_session('AKIA_3')]
        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'work', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            custom_config.write_text('[default]\nregion = us-west-2\n', encoding='utf-8')
            _bump_mtime(custom_config)
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'work', False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

            custom_creds.write_text('[default]\naws_access_key_id = AKIA3\n', encoding='utf-8')
            _bump_mtime(custom_creds)
            req3 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'work', False, req3)
            assert _extract_access_key(req3) == 'AKIA_3'

        assert mock_create.call_count == 3

    @pytest.mark.asyncio
    async def test_rebuilds_when_sso_cache_file_added_overwritten_in_place_or_deleted(
        self, isolated_aws_fs: Path
    ):
        """Adding, overwriting in place, or removing a file in ~/.aws/sso/cache invalidates."""
        sso_cache = isolated_aws_fs / '.aws' / 'sso' / 'cache'
        token_file = sso_cache / 'abcdef1234.json'
        sessions = [
            _make_session('AKIA_1'),
            _make_session('AKIA_2'),
            _make_session('AKIA_3'),
            _make_session('AKIA_4'),
        ]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            # Initial session cached with empty sso cache dir
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            # 1. File created (aws sso login)
            token_file.write_text('{"accessToken": "tok-v1"}', encoding='utf-8')
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

            # 2. File overwritten in place without changing dir mtime (same length!)
            dir_stat_before = sso_cache.stat()
            token_file.write_text('{"accessToken": "tok-v2"}', encoding='utf-8')
            _bump_mtime(token_file)
            os.utime(sso_cache, (dir_stat_before.st_atime, dir_stat_before.st_mtime))
            req3 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req3)
            assert _extract_access_key(req3) == 'AKIA_3'

            # 3. File deleted (aws sso logout)
            token_file.unlink()
            req4 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req4)
            assert _extract_access_key(req4) == 'AKIA_4'

        assert mock_create.call_count == 4

    @pytest.mark.asyncio
    async def test_rebuilds_when_cli_cache_changes(self, isolated_aws_fs: Path):
        """External updates to ~/.aws/cli/cache invalidate the cached session."""
        cli_cache = isolated_aws_fs / '.aws' / 'cli' / 'cache'
        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2')]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            (cli_cache / 'role-creds.json').write_text('{"Credentials": {}}', encoding='utf-8')
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_rebuilds_when_login_cache_changes(
        self, isolated_aws_fs: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Updates to AWS_LOGIN_CACHE_DIRECTORY (or ~/.aws/login/cache) invalidate the session."""
        login_dir = isolated_aws_fs / 'custom_login_cache'
        login_dir.mkdir()
        monkeypatch.setenv('AWS_LOGIN_CACHE_DIRECTORY', str(login_dir))
        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2')]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'login-prof', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            (login_dir / 'session.json').write_text('{"accessToken": "new"}', encoding='utf-8')
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'login-prof', False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_rebuilds_when_web_identity_token_file_changes(
        self, isolated_aws_fs: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Modifying AWS_WEB_IDENTITY_TOKEN_FILE invalidates the cached session."""
        token_path = isolated_aws_fs / 'web-identity-token'
        token_path.write_text('jwt-v1', encoding='utf-8')
        monkeypatch.setenv('AWS_WEB_IDENTITY_TOKEN_FILE', str(token_path))
        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2')]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            token_path.write_text('jwt-v2-rotated', encoding='utf-8')
            _bump_mtime(token_path)
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_broken_symlink_in_cache_dir_does_not_break_caching(self, isolated_aws_fs: Path):
        """A broken symlink inside a cache dir is ignored safely without failing signing."""
        sso_cache = isolated_aws_fs / '.aws' / 'sso' / 'cache'
        broken_link = sso_cache / 'dangling.json'
        broken_link.symlink_to(isolated_aws_fs / 'nonexistent-target.json')

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            return_value=_make_session('AKIA_OK'),
        ) as mock_create:
            for _ in range(2):
                req = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
                await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req)
                assert _extract_access_key(req) == 'AKIA_OK'

        assert mock_create.call_count == 1


class TestEnvVarInvalidation:
    """Verify AWS credential/profile environment variable changes invalidate the cache."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('env_var', 'initial_value', 'updated_value'),
        [
            ('AWS_ACCESS_KEY_ID', 'AKIAOLD1', 'AKIANEW2'),
            ('AWS_SECRET_ACCESS_KEY', 'secret-old', 'secret-new'),
            ('AWS_SESSION_TOKEN', 'token-old', 'token-new'),
            ('AWS_PROFILE', 'dev', 'prod'),
            ('AWS_REGION', 'us-east-1', 'eu-west-1'),
        ],
    )
    async def test_rebuilds_when_aws_env_var_changes(
        self,
        monkeypatch: pytest.MonkeyPatch,
        env_var: str,
        initial_value: str,
        updated_value: str,
    ):
        """Changing an AWS credential/config env var triggers a session rebuild."""
        monkeypatch.setenv(env_var, initial_value)
        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2')]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            monkeypatch.setenv(env_var, updated_value)
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', None, False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_unrelated_env_var_does_not_invalidate_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Changing an unrelated environment variable keeps the cached session."""
        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            return_value=_make_session('AKIA_SAME'),
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)

            monkeypatch.setenv('UNRELATED_APP_SETTING', 'changed')
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)

        assert mock_create.call_count == 1


class TestExpiryAndAuthErrorInvalidation:
    """Verify near-expiry credentials, 401/403 responses, and signing errors refresh sessions."""

    @pytest.mark.asyncio
    async def test_rebuilds_when_refreshable_credentials_are_near_expiry(self):
        """Refreshable credentials nearing expiry trigger a fresh session on the next request."""
        expiring_soon = RefreshableCredentials.create_from_metadata(
            metadata={
                'access_key': 'ASIA_EXPIRING',
                'secret_key': 'secret-1',
                'token': 'token-1',
                'expiry_time': (datetime.now(UTC) + timedelta(seconds=20)).isoformat(),
            },
            refresh_using=lambda: {
                'access_key': 'ASIA_EXPIRING',
                'secret_key': 'secret-1',
                'token': 'token-1',
                'expiry_time': (datetime.now(UTC) + timedelta(seconds=20)).isoformat(),
            },
            method='sso',
        )
        fresh = RefreshableCredentials.create_from_metadata(
            metadata={
                'access_key': 'ASIA_FRESH',
                'secret_key': 'secret-2',
                'token': 'token-2',
                'expiry_time': (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
            refresh_using=lambda: {
                'access_key': 'ASIA_FRESH',
                'secret_key': 'secret-2',
                'token': 'token-2',
                'expiry_time': (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
            method='sso',
        )
        session_1 = MagicMock()
        session_1.get_credentials.return_value = expiring_soon
        session_2 = MagicMock()
        session_2.get_credentials.return_value = fresh

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=[session_1, session_2],
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'ASIA_EXPIRING'

            # Next request sees the cached credentials are near expiry and rebuilds
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'ASIA_FRESH'

            # Third request reuses the fresh session (expires in 1 hour)
            req3 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req3)
            assert _extract_access_key(req3) == 'ASIA_FRESH'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize('status', [401, 403])
    async def test_rebuilds_after_401_or_403_response(self, status: int):
        """A 401 or 403 response invalidates the cached session for the next request."""
        sessions = [_make_session('AKIA_STALE'), _make_session('AKIA_REFRESHED')]
        seen_keys: list[str] = []
        call_num = 0

        def handler(request: httpx2.Request) -> httpx2.Response:
            nonlocal call_num
            call_num += 1
            seen_keys.append(_extract_access_key(request))
            if call_num == 1:
                return httpx2.Response(status, text='ExpiredTokenException')
            return httpx2.Response(200, json={'jsonrpc': '2.0', 'id': 2, 'result': {}})

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            client = create_sigv4_client(
                service='execute-api',
                region='us-east-1',
                profile='sso-profile',
                transport=httpx2.MockTransport(handler),
            )
            async with client:
                await client.post(
                    'https://example.com/mcp',
                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                )
                await client.post(
                    'https://example.com/mcp',
                    json={'jsonrpc': '2.0', 'id': 2, 'method': 'ping'},
                )
                # Third request after recovery reuses the refreshed session
                await client.post(
                    'https://example.com/mcp',
                    json={'jsonrpc': '2.0', 'id': 3, 'method': 'ping'},
                )

        assert mock_create.call_count == 2
        assert seen_keys == ['AKIA_STALE', 'AKIA_REFRESHED', 'AKIA_REFRESHED']

    @pytest.mark.asyncio
    async def test_rebuilds_on_400_with_expired_token_error_but_not_ordinary_400(self):
        """A 400 reporting expired/invalid credentials invalidates; an ordinary 400 does not."""
        sessions = [
            _make_session('AKIA_1'),
            _make_session('AKIA_2'),
            _make_session('AKIA_3'),
        ]
        responses = [
            httpx2.Response(400, json={'error': 'invalid parameter'}),
            httpx2.Response(
                400,
                headers={'x-amzn-errortype': 'ExpiredTokenException'},
                json={'message': 'The security token included in the request is expired'},
            ),
            httpx2.Response(
                400,
                json={'__type': 'InvalidSignatureException', 'message': 'Signature expired'},
            ),
            httpx2.Response(200, json={'jsonrpc': '2.0', 'id': 4, 'result': {}}),
        ]
        seen_keys: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen_keys.append(_extract_access_key(request))
            return responses.pop(0)

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            client = create_sigv4_client(
                service='execute-api',
                region='us-east-1',
                profile='sso',
                transport=httpx2.MockTransport(handler),
            )
            async with client:
                for i in range(4):
                    await client.post('https://example.com/mcp', json={'id': i})

        # Ordinary 400 kept AKIA_1; header-based 400 rebuilt to AKIA_2; body-based 400 rebuilt to AKIA_3
        assert mock_create.call_count == 3
        assert seen_keys == ['AKIA_1', 'AKIA_1', 'AKIA_2', 'AKIA_3']

    @pytest.mark.asyncio
    @pytest.mark.parametrize('status', [404, 500])
    async def test_non_auth_error_responses_do_not_invalidate_cache(self, status: int):
        """Non-auth HTTP errors (404, 500) do not discard the cached session."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(status, text='server error')

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            return_value=_make_session('AKIA_KEEP'),
        ) as mock_create:
            client = create_sigv4_client(
                service='execute-api',
                region='us-east-1',
                profile='sso',
                transport=httpx2.MockTransport(handler),
            )
            async with client:
                await client.post('https://example.com/mcp', json={'id': 1})
                await client.post('https://example.com/mcp', json={'id': 2})

        assert mock_create.call_count == 1

    @pytest.mark.asyncio
    async def test_late_401_from_old_session_does_not_evict_refreshed_session(
        self, isolated_aws_fs: Path
    ):
        """A delayed 401 from an older session must not invalidate a newer cached session."""
        sessions = [_make_session('AKIA_1'), _make_session('AKIA_2')]

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=sessions,
        ) as mock_create:
            # Request 1 signed with session 1
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            # Disk updates before req1's response returns -> req2 refreshes to session 2
            config_file = isolated_aws_fs / '.aws' / 'config'
            config_file.write_text('[default]\nregion = ap-northeast-1\n', encoding='utf-8')
            _bump_mtime(config_file)

            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'AKIA_2'

            # Now req1's delayed 401 response arrives
            stale_401 = httpx2.Response(401, content=b'Unauthorized', request=req1)
            await _handle_error_response(stale_401)

            # Request 3 MUST still reuse session 2 (not rebuild a third time)
            req3 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req3)
            assert _extract_access_key(req3) == 'AKIA_2'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_signing_failure_invalidates_cached_session(self):
        """If deferred credential fetch fails during signing, the next request rebuilds."""
        failing_session = MagicMock()
        failing_session.get_credentials.return_value = DeferredRefreshableCredentials(
            refresh_using=lambda: (_ for _ in ()).throw(RuntimeError('SSO token expired')),
            method='sso',
        )
        good_session = _make_session('AKIA_RECOVERED')

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=[failing_session, good_session],
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            with pytest.raises(RuntimeError, match='SSO token expired'):
                await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)

            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)
            assert _extract_access_key(req2) == 'AKIA_RECOVERED'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_none_credentials_are_not_cached(self):
        """A session yielding None credentials is not cached across requests."""
        empty_session = MagicMock()
        empty_session.get_credentials.return_value = None
        valid_session = _make_session('AKIA_LATER')

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=[empty_session, valid_session],
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', True, req1)
            assert 'authorization' not in req1.headers

            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', True, req2)
            assert _extract_access_key(req2) == 'AKIA_LATER'

        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_failed_rebuild_evicts_stale_entry(self, isolated_aws_fs: Path):
        """A failed rebuild after disk change evicts the stale entry instead of keeping it."""
        config_file = isolated_aws_fs / '.aws' / 'config'
        original_content = config_file.read_text(encoding='utf-8')
        original_stat = config_file.stat()

        sessions = [
            _make_session('AKIA_1'),
            ValueError('Broken config'),
            _make_session('AKIA_3'),
        ]

        def create_side_effect(_profile):
            item = sessions.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=create_side_effect,
        ) as mock_create:
            req1 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req1)
            assert _extract_access_key(req1) == 'AKIA_1'

            config_file.write_text('[broken', encoding='utf-8')
            _bump_mtime(config_file)
            req2 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            with pytest.raises(ValueError, match='Broken config'):
                await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req2)

            # Even if timestamps somehow reverted, stale AKIA_1 must not be reused
            config_file.write_text(original_content, encoding='utf-8')
            os.utime(config_file, (original_stat.st_atime, original_stat.st_mtime))
            req3 = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            await _sign_request_hook('us-east-1', 'execute-api', 'sso', False, req3)
            assert _extract_access_key(req3) == 'AKIA_3'

        assert mock_create.call_count == 3


class TestConcurrencySafety:
    """Verify thread and async concurrency safety of session caching."""

    def test_concurrent_threads_build_session_once_for_same_profile(self):
        """Multiple threads signing concurrently for the same profile only create one session."""
        barrier = threading.Barrier(6)
        create_calls = 0
        count_lock = threading.Lock()

        def slow_create_session(_profile: str | None = None):
            nonlocal create_calls
            with count_lock:
                create_calls += 1
            return _make_session('AKIA_SHARED')

        def worker() -> str:
            barrier.wait(timeout=5)
            req = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            asyncio.run(_sign_request_hook('us-east-1', 'execute-api', 'shared', False, req))
            return _extract_access_key(req)

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=slow_create_session,
        ):
            with ThreadPoolExecutor(max_workers=6) as pool:
                keys = list(pool.map(lambda _: worker(), range(6)))

        assert create_calls == 1
        assert keys == ['AKIA_SHARED'] * 6

    def test_concurrent_different_profiles_do_not_block_each_other(self):
        """A slow session creation for profile A does not block profile B."""
        profile_a_entered = threading.Event()
        release_profile_a = threading.Event()

        def create_side_effect(profile: str | None = None):
            if profile == 'profile-a':
                profile_a_entered.set()
                assert release_profile_a.wait(timeout=5), 'profile-b should not block profile-a'
                return _make_session('AKIA_A')
            return _make_session('AKIA_B')

        def sign_profile(profile: str) -> str:
            req = httpx2.Request('POST', 'https://example.com/mcp', content=b'{}')
            asyncio.run(_sign_request_hook('us-east-1', 'execute-api', profile, False, req))
            return _extract_access_key(req)

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            side_effect=create_side_effect,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                future_a = pool.submit(sign_profile, 'profile-a')
                assert profile_a_entered.wait(timeout=5)
                # While profile-a is blocked inside create_aws_session, profile-b finishes
                assert sign_profile('profile-b') == 'AKIA_B'
                release_profile_a.set()
                assert future_a.result(timeout=5) == 'AKIA_A'

    @pytest.mark.asyncio
    async def test_concurrent_async_requests_share_single_session(self):
        """Concurrent async requests through create_sigv4_client reuse one session."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, json={'jsonrpc': '2.0', 'id': 1, 'result': {}})

        with patch(
            'mcp_proxy_for_aws.sigv4_helper.create_aws_session',
            return_value=_make_session('AKIA_ASYNC'),
        ) as mock_create:
            client = create_sigv4_client(
                service='execute-api',
                region='us-east-1',
                profile='sso-async',
                transport=httpx2.MockTransport(handler),
            )
            async with client:
                responses = await asyncio.gather(
                    *(client.post('https://example.com/mcp', json={'id': i}) for i in range(10))
                )

        assert all(resp.status_code == 200 for resp in responses)
        assert mock_create.call_count == 1
