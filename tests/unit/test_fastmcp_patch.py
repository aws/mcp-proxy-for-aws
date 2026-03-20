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

"""Tests for fastmcp_patch module.

The McpError handling during initialize that was previously monkey-patched
is now handled natively in FastMCP 3.x. The patch module is a no-op.
"""


def test_fastmcp_patch_module_imports():
    """Test that the fastmcp_patch module can be imported (no-op)."""
    import mcp_proxy_for_aws.fastmcp_patch  # noqa: F401
