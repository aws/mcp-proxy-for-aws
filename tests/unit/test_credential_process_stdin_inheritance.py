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

"""Stress test and validation for D454977820: credential_process stdin inheritance on Windows.

Issue: When mcp-proxy-for-aws runs in stdio transport mode, botocore's ProcessProvider
spawns credential_process subprocesses without specifying stdin. The child inherits the
MCP JSON-RPC pipe as its stdin. On Windows (IOCP), this causes Popen.communicate() to
hang indefinitely because the child holds an open handle to the pipe.

Proposed fix: Monkey-patch ProcessProvider._retrieve_credentials_using to pass
stdin=subprocess.DEVNULL when spawning credential_process.
"""

import json
import os
import pytest
import subprocess
import sys
import threading
from botocore.credentials import ProcessProvider
from unittest.mock import MagicMock, patch


class TestCredentialProcessStdinInheritanceIssue:
    """Validate that the stdin inheritance issue exists and the fix works."""

    def test_process_provider_passes_stdin_devnull_after_patch(self):
        """Confirm our monkey-patch is active: ProcessProvider._popen injects stdin=DEVNULL."""
        import mcp_proxy_for_aws.sigv4_helper  # noqa: F401 - ensure patch is applied

        popen_kwargs = {}

        def mock_popen(*args, **kwargs):
            popen_kwargs.update(kwargs)
            mock = MagicMock()
            mock.returncode = 0
            mock.communicate.return_value = (
                b'{"Version":1,"AccessKeyId":"A","SecretAccessKey":"B"}',
                b'',
            )
            return mock

        provider = ProcessProvider(
            profile_name='test',
            load_config=lambda: {'profiles': {'test': {'credential_process': 'echo hi'}}},
            popen=mock_popen,  # type: ignore[arg-type]
        )
        provider.load()
        assert popen_kwargs.get('stdin') == subprocess.DEVNULL, (
            'The monkey-patch for stdin=subprocess.DEVNULL is not active — '
            'credential_process will hang on Windows in stdio mode'
        )

    def test_subprocess_inherits_stdin_by_default(self):
        """Demonstrate that subprocess.Popen inherits stdin when not specified."""
        # Create a pipe to simulate the MCP stdio transport
        read_fd, write_fd = os.pipe()

        try:
            # Write some data to simulate MCP traffic on the pipe
            os.write(write_fd, b'{"jsonrpc": "2.0", "method": "initialize"}\n')

            # Spawn a process the same way botocore does (no stdin kwarg)
            # Use a command that reads from stdin and exits
            if sys.platform == 'win32':
                cmd = ['cmd', '/c', 'echo ok']
            else:
                cmd = ['echo', 'ok']

            # Replace our stdin with the pipe temporarily
            original_stdin = os.dup(0)
            os.dup2(read_fd, 0)

            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = p.communicate(timeout=5)
                # The process completed, but on Windows with a real pipe this would hang
                assert p.returncode == 0
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_subprocess_with_devnull_stdin_does_not_inherit(self):
        """Demonstrate that stdin=DEVNULL prevents pipe inheritance."""
        read_fd, write_fd = os.pipe()

        try:
            os.write(write_fd, b'{"jsonrpc": "2.0", "method": "initialize"}\n')

            original_stdin = os.dup(0)
            os.dup2(read_fd, 0)

            try:
                if sys.platform == 'win32':
                    cmd = ['cmd', '/c', 'echo ok']
                else:
                    cmd = ['echo', 'ok']

                # With stdin=DEVNULL, child does NOT inherit the MCP pipe
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )
                stdout, _ = p.communicate(timeout=5)
                assert p.returncode == 0
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(read_fd)
            os.close(write_fd)


class TestMonkeyPatchSolution:
    """Validate that the proposed monkey-patch solution works correctly."""

    def _create_monkey_patch(self):
        """Create the monkey-patch that fixes the stdin inheritance issue.

        This is the proposed fix from awouters: patch ProcessProvider to pass
        stdin=subprocess.DEVNULL when spawning credential_process.
        """

        def _patched_retrieve_credentials_using(self, credential_process):
            from botocore.compat import compat_shell_split
            from botocore.exceptions import CredentialRetrievalError

            process_list = compat_shell_split(credential_process)
            p = self._popen(
                process_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                raise CredentialRetrievalError(
                    provider=self.METHOD, error_msg=stderr.decode('utf-8')
                )
            import botocore.compat

            parsed = botocore.compat.json.loads(stdout.decode('utf-8'))
            version = parsed.get('Version', '<Version key not provided>')
            if version != 1:
                raise CredentialRetrievalError(
                    provider=self.METHOD,
                    error_msg=f'Unsupported version {version} in credential_process output',
                )
            try:
                return {
                    'access_key': parsed['AccessKeyId'],
                    'secret_key': parsed['SecretAccessKey'],
                    'token': parsed.get('SessionToken'),
                    'expiry_time': parsed.get('Expiration'),
                    'account_id': parsed.get('AccountId'),
                }
            except KeyError as e:
                raise CredentialRetrievalError(
                    provider=self.METHOD,
                    error_msg=f'Missing required key {e} in credential_process output',
                )

        return _patched_retrieve_credentials_using

    def test_monkey_patch_passes_stdin_devnull(self):
        """Verify the monkey-patch passes stdin=subprocess.DEVNULL to Popen."""
        popen_calls = []

        class MockPopen:
            def __init__(self, *args, **kwargs):
                popen_calls.append((args, kwargs))
                self.returncode = 0

            def communicate(self):
                creds = json.dumps(
                    {
                        'Version': 1,
                        'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                        'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                        'SessionToken': 'FwoGZXIvYXdzEBY...',
                        'Expiration': '2026-05-28T00:00:00Z',
                    }
                )
                return creds.encode('utf-8'), b''

        patched_fn = self._create_monkey_patch()

        provider = MagicMock(spec=ProcessProvider)
        provider._popen = MockPopen
        provider.METHOD = 'custom-process'

        result = patched_fn(provider, 'echo creds')

        assert len(popen_calls) == 1
        _, kwargs = popen_calls[0]
        assert kwargs.get('stdin') == subprocess.DEVNULL, (
            'Monkey-patch must pass stdin=subprocess.DEVNULL to prevent pipe inheritance'
        )
        assert kwargs.get('stdout') == subprocess.PIPE
        assert kwargs.get('stderr') == subprocess.PIPE
        assert result['access_key'] == 'AKIAIOSFODNN7EXAMPLE'

    def test_monkey_patch_preserves_error_handling(self):
        """Verify the monkey-patch preserves error handling for failed processes."""
        from botocore.exceptions import CredentialRetrievalError

        class MockPopen:
            def __init__(self, *args, **kwargs):
                self.returncode = 1

            def communicate(self):
                return b'', b'credential process failed: permission denied'

        patched_fn = self._create_monkey_patch()

        provider = MagicMock(spec=ProcessProvider)
        provider._popen = MockPopen
        provider.METHOD = 'custom-process'

        with pytest.raises(CredentialRetrievalError):
            patched_fn(provider, 'failing-credential-command')

    def test_monkey_patch_handles_invalid_version(self):
        """Verify the monkey-patch rejects unsupported credential versions."""
        from botocore.exceptions import CredentialRetrievalError

        class MockPopen:
            def __init__(self, *args, **kwargs):
                self.returncode = 0

            def communicate(self):
                return json.dumps({'Version': 2, 'AccessKeyId': 'X'}).encode(), b''

        patched_fn = self._create_monkey_patch()

        provider = MagicMock(spec=ProcessProvider)
        provider._popen = MockPopen
        provider.METHOD = 'custom-process'

        with pytest.raises(CredentialRetrievalError):
            patched_fn(provider, 'version2-creds')


class TestStdioTransportWithCredentialProcess:
    """Integration-style tests simulating the stdio transport + credential_process scenario."""

    def test_credential_process_with_simulated_mcp_pipe_no_hang(self):
        """Simulate the actual failure scenario: MCP pipe as stdin + credential_process.

        Without the fix, communicate() would hang on Windows because the child
        holds the pipe handle open. With stdin=DEVNULL, the child doesn't inherit
        the pipe and communicate() returns immediately.
        """
        # Create a pipe simulating the MCP stdio transport
        mcp_read_fd, mcp_write_fd = os.pipe()

        try:
            # Simulate MCP traffic on the pipe (data the child should NOT see)
            os.write(mcp_write_fd, b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')

            # Replace stdin with our MCP pipe
            original_stdin = os.dup(0)
            os.dup2(mcp_read_fd, 0)

            try:
                # This simulates what the fix does: spawn with stdin=DEVNULL
                if sys.platform == 'win32':
                    cmd = [
                        'cmd',
                        '/c',
                        'echo {"Version":1,"AccessKeyId":"A","SecretAccessKey":"B"}',
                    ]
                else:
                    cmd = [
                        sys.executable,
                        '-c',
                        'import json; print(json.dumps({"Version":1,"AccessKeyId":"A","SecretAccessKey":"B"}))',
                    ]

                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )

                # This should NOT hang even though our real stdin is a pipe
                stdout, stderr = p.communicate(timeout=10)
                assert p.returncode == 0

                creds = json.loads(stdout.decode('utf-8'))
                assert creds['Version'] == 1
                assert creds['AccessKeyId'] == 'A'
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(mcp_read_fd)
            os.close(mcp_write_fd)

    def test_concurrent_credential_process_calls_with_mcp_pipe(self):
        """Stress test: multiple concurrent credential_process calls with active MCP pipe.

        This simulates the real-world scenario where multiple tool calls trigger
        credential refresh concurrently while the MCP pipe is active.
        """
        mcp_read_fd, mcp_write_fd = os.pipe()
        results = []
        errors = []

        def spawn_credential_process(index):
            try:
                cmd = [
                    sys.executable,
                    '-c',
                    f'import json, time; time.sleep(0.1); print(json.dumps({{"Version":1,"AccessKeyId":"KEY{index}","SecretAccessKey":"SECRET{index}"}}))',
                ]
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )
                stdout, _ = p.communicate(timeout=10)
                creds = json.loads(stdout.decode('utf-8'))
                results.append((index, creds))
            except Exception as e:
                errors.append((index, e))

        try:
            os.write(mcp_write_fd, b'{"jsonrpc":"2.0"}\n' * 100)

            original_stdin = os.dup(0)
            os.dup2(mcp_read_fd, 0)

            try:
                threads = []
                for i in range(10):
                    t = threading.Thread(target=spawn_credential_process, args=(i,))
                    threads.append(t)
                    t.start()

                for t in threads:
                    t.join(timeout=15)

                assert len(errors) == 0, f'Errors occurred: {errors}'
                assert len(results) == 10, f'Expected 10 results, got {len(results)}'

                # Verify each credential process returned unique creds
                keys = {r[1]['AccessKeyId'] for r in results}
                assert len(keys) == 10
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(mcp_read_fd)
            os.close(mcp_write_fd)

    def test_credential_process_timeout_without_fix(self):
        """Demonstrate that without stdin=DEVNULL, a reading child can block.

        This test uses a child that reads from stdin. Without DEVNULL, it would
        try to read from the MCP pipe and block. With DEVNULL, it gets EOF immediately.
        """
        mcp_read_fd, mcp_write_fd = os.pipe()

        try:
            # Put data on the pipe that could confuse the child
            os.write(mcp_write_fd, b'{"jsonrpc":"2.0","method":"initialize"}\n')

            original_stdin = os.dup(0)
            os.dup2(mcp_read_fd, 0)

            try:
                # Child that tries to read stdin — with DEVNULL it gets EOF immediately
                cmd = [
                    sys.executable,
                    '-c',
                    'import sys, json; '
                    'data = sys.stdin.read(); '  # Would block on pipe without DEVNULL
                    'print(json.dumps({"Version":1,"AccessKeyId":"A","SecretAccessKey":"B"}))',
                ]

                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )

                # Should complete quickly since stdin is /dev/null (EOF)
                stdout, stderr = p.communicate(timeout=5)
                assert p.returncode == 0
                creds = json.loads(stdout.decode('utf-8'))
                assert creds['AccessKeyId'] == 'A'
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(mcp_read_fd)
            os.close(mcp_write_fd)

    def test_without_fix_child_inherits_pipe_data(self):
        """Show that without stdin=DEVNULL, the child CAN read MCP pipe data.

        This proves the vulnerability: without the fix, credential_process could
        read (and consume) data meant for the MCP proxy from the pipe.
        """
        mcp_read_fd, mcp_write_fd = os.pipe()
        mcp_message = '{"jsonrpc":"2.0","id":42,"method":"tools/list"}\n'

        try:
            os.write(mcp_write_fd, mcp_message.encode())
            os.close(mcp_write_fd)  # Close write end so child gets EOF after the data

            original_stdin = os.dup(0)
            os.dup2(mcp_read_fd, 0)

            try:
                # Child reads from inherited stdin (the MCP pipe) — BAD!
                cmd = [
                    sys.executable,
                    '-c',
                    'import sys; data = sys.stdin.readline(); print(repr(data))',
                ]

                # WITHOUT fix: no stdin= arg, child inherits the pipe
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Note: no stdin=subprocess.DEVNULL — this is the UNFIXED behavior
                )
                stdout, _ = p.communicate(timeout=5)

                # The child was able to read MCP data — this is the bug!
                child_output = stdout.decode('utf-8').strip()
                assert 'tools/list' in child_output, (
                    'Child should have read the MCP message from inherited stdin'
                )
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(mcp_read_fd)


class TestProposedFixIntegration:
    """Test the fix integrated into the actual sigv4_helper flow."""

    def test_create_aws_session_with_credential_process_profile(self, tmp_path):
        """Test create_aws_session works with a credential_process profile."""
        # Create a fake AWS config with credential_process
        config_file = tmp_path / 'config'
        cred_script = tmp_path / 'creds.py'

        cred_script.write_text(
            'import json\n'
            'print(json.dumps({"Version": 1, "AccessKeyId": "AKTEST", '
            '"SecretAccessKey": "SECRET", "SessionToken": "TOKEN", '
            '"Expiration": "2099-01-01T00:00:00Z"}))\n'
        )

        config_file.write_text(
            '[profile test-credproc]\n'
            'output = json\n'
            'region = us-east-1\n'
            f'credential_process = {sys.executable} {cred_script}\n'
        )

        env_patch = {
            'AWS_CONFIG_FILE': str(config_file),
            'AWS_SHARED_CREDENTIALS_FILE': str(tmp_path / 'nonexistent'),
        }

        with patch.dict(os.environ, env_patch, clear=False):
            import boto3

            session = boto3.Session(profile_name='test-credproc')
            credentials = session.get_credentials()
            # Force credential resolution (this calls credential_process)
            frozen = credentials.get_frozen_credentials()
            assert frozen.access_key == 'AKTEST'
            assert frozen.secret_key == 'SECRET'
            assert frozen.token == 'TOKEN'

    def test_create_aws_session_credential_process_with_mcp_pipe(self, tmp_path):
        """End-to-end: credential_process resolves even when stdin is an MCP pipe."""
        config_file = tmp_path / 'config'
        cred_script = tmp_path / 'creds.py'

        # Script that would hang if it inherited an open pipe as stdin
        # (reads stdin to prove it gets EOF from DEVNULL, not MCP data)
        cred_script.write_text(
            'import json, sys\n'
            'stdin_data = sys.stdin.read()  # Should be empty with DEVNULL\n'
            'assert stdin_data == "", f"Got unexpected stdin data: {stdin_data!r}"\n'
            'print(json.dumps({"Version": 1, "AccessKeyId": "PIPE_TEST", '
            '"SecretAccessKey": "S", "SessionToken": "T", '
            '"Expiration": "2099-01-01T00:00:00Z"}))\n'
        )

        config_file.write_text(
            f'[profile pipetest]\ncredential_process = {sys.executable} {cred_script}\n'
        )

        # Set up MCP pipe as stdin
        mcp_read_fd, mcp_write_fd = os.pipe()

        try:
            os.write(mcp_write_fd, b'{"jsonrpc":"2.0"}\n')

            original_stdin = os.dup(0)
            os.dup2(mcp_read_fd, 0)

            try:
                env_patch = {
                    'AWS_CONFIG_FILE': str(config_file),
                    'AWS_SHARED_CREDENTIALS_FILE': str(tmp_path / 'nonexistent'),
                }

                # Apply the monkey-patch
                original_retrieve = ProcessProvider._retrieve_credentials_using

                def patched_retrieve(self, credential_process):
                    from botocore.compat import compat_shell_split

                    process_list = compat_shell_split(credential_process)
                    p = self._popen(
                        process_list,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                    )
                    stdout, stderr = p.communicate()
                    if p.returncode != 0:
                        from botocore.exceptions import CredentialRetrievalError

                        raise CredentialRetrievalError(
                            provider=self.METHOD,
                            error_msg=stderr.decode('utf-8'),
                        )
                    import botocore.compat

                    parsed = botocore.compat.json.loads(stdout.decode('utf-8'))
                    version = parsed.get('Version', '<Version key not provided>')
                    if version != 1:
                        from botocore.exceptions import CredentialRetrievalError

                        raise CredentialRetrievalError(
                            provider=self.METHOD,
                            error_msg=f'Unsupported version {version}',
                        )
                    return {
                        'access_key': parsed['AccessKeyId'],
                        'secret_key': parsed['SecretAccessKey'],
                        'token': parsed.get('SessionToken'),
                        'expiry_time': parsed.get('Expiration'),
                        'account_id': parsed.get('AccountId'),
                    }

                ProcessProvider._retrieve_credentials_using = patched_retrieve

                try:
                    with patch.dict(os.environ, env_patch, clear=False):
                        import boto3

                        session = boto3.Session(profile_name='pipetest')
                        credentials = session.get_credentials()
                        frozen = credentials.get_frozen_credentials()
                        assert frozen.access_key == 'PIPE_TEST'
                finally:
                    ProcessProvider._retrieve_credentials_using = original_retrieve
            finally:
                os.dup2(original_stdin, 0)
                os.close(original_stdin)
        finally:
            os.close(mcp_read_fd)
            os.close(mcp_write_fd)
