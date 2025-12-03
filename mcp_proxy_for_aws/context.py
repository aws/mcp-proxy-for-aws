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

"""Module-level storage for session-scoped data."""

from mcp.types import Implementation
from typing import Optional


_client_info: Optional[Implementation] = None


def get_client_info() -> Optional[Implementation]:
    """Get the stored client info."""
    return _client_info


def set_client_info(info: Optional[Implementation]) -> None:
    """Set the client info."""
    global _client_info
    _client_info = info
