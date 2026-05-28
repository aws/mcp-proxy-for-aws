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

"""Tests for the credential_process stdin isolation patch in sigv4_helper.

When mcp-proxy-for-aws runs in stdio transport mode, its stdin is the MCP
JSON-RPC pipe. Without the patch, botocore's ProcessProvider would spawn
credential_process subprocesses that inherit the pipe, causing hangs on Windows.
"""

import mcp_proxy_for_aws.sigv4_helper  # noqa: F401 - ensure patch is applied
import subprocess
from botocore.credentials import ProcessProvider
from unittest.mock import MagicMock


class TestCredentialProcessStdinPatch:
    """Verify the sigv4_helper patch injects stdin=DEVNULL into ProcessProvider."""

    def test_popen_receives_stdin_devnull(self):
        """ProcessProvider._popen passes stdin=subprocess.DEVNULL after the patch."""
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
        assert popen_kwargs.get('stdin') == subprocess.DEVNULL

    def test_explicit_stdin_is_not_overridden(self):
        """If caller explicitly sets stdin, the patch does not override it."""
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

        # Call _popen directly with an explicit stdin to verify setdefault behavior
        provider._popen('echo', stdin=subprocess.PIPE)
        assert popen_kwargs.get('stdin') == subprocess.PIPE

    def test_credential_process_error_propagates(self):
        """The patch does not swallow errors from credential_process."""
        from botocore.exceptions import CredentialRetrievalError

        def mock_popen(*args, **kwargs):
            mock = MagicMock()
            mock.returncode = 1
            mock.communicate.return_value = (b'', b'access denied')
            return mock

        provider = ProcessProvider(
            profile_name='test',
            load_config=lambda: {'profiles': {'test': {'credential_process': 'fail'}}},
            popen=mock_popen,  # type: ignore[arg-type]
        )

        import pytest

        with pytest.raises(CredentialRetrievalError):
            provider.load()
