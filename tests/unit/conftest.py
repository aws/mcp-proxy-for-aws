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

"""Shared fixtures for unit tests."""

import pytest


@pytest.fixture(autouse=True)
def _reset_sensitive_headers():
    """Keep the process-global sensitive-header set from leaking between tests.

    `register_sensitive_headers` mutates module state that is never cleared in
    normal operation, so without this a test that registers a name leaves it
    registered for the rest of the session and a later test can pass for the
    wrong reason.
    """
    from mcp_proxy_for_aws import sigv4_helper

    snapshot = set(sigv4_helper._EXTRA_SENSITIVE_HEADERS)
    yield
    sigv4_helper._EXTRA_SENSITIVE_HEADERS.clear()
    sigv4_helper._EXTRA_SENSITIVE_HEADERS.update(snapshot)
